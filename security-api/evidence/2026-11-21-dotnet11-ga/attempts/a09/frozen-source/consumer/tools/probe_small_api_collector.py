"""Frozen twelve-run collector preparation probe, not an acceptance benchmark.

Reuse the canonical environment/identity/fixture preflight and owned server
lifetime. Coherent driver failures are observations; incomplete evidence aborts
the attempt. Never repeat a failed run or enter warmup/measured load here.
"""
import argparse
import gzip
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
import traceback

from small_api_collector_evidence import validate_collector_preparation, validate_phase_telemetry, validate_preflight_rejection

from benchmark_small_api import (
    DRIVER_CPUS, ROOT, InfrastructureFailure, Runner, Server, stamp, write_json,
)

PAIR_ORDER = ('BE', 'EB', 'BE')
RATE, SECONDS, OFFERED = 2000, 2, 4000
PLANNED_MEASURED_SECONDS, PLANNED_WARMUP_SECONDS, PLANNED_MANIFEST = 180, 60, 360000


def require(condition, message):
    if not condition:
        raise InfrastructureFailure(message)


def read_json(path):
    try:
        return json.loads(Path(path).read_text(encoding='utf-8'))
    except (OSError, ValueError) as error:
        raise InfrastructureFailure('Missing/incomplete probe evidence: ' + str(path)) from error


def validate_result(directory, transport, exit_code):
    """Validate evidence shape/accounting, without converting a failure to pass."""
    report = read_json(directory / 'preflight-result.json')
    require(report.get('schemaVersion') == 1 and report.get('mode') == 'preflight-only', 'Unsupported preflight-only result schema.')
    require(report.get('transport') == transport and report.get('rate') == RATE and report.get('offeredCount') == OFFERED and report.get('seconds') == SECONDS, 'Probe workload differs from the frozen declaration.')
    status = report.get('status')
    require(status in ('passed', 'collector-preflight-failed'), 'Driver result is not a coherent completed preflight observation.')
    require(exit_code == (0 if status == 'passed' else 1), 'Driver did not return the documented managed pass/guard code; arbitrary crashes are invalid.')
    require(report.get('enteredPhases') == ['preflight'] and report.get('warmupEntered') is False and report.get('measuredEntered') is False, 'Probe phase entry history differs from preflight-only scope.')
    preparation = report.get('preparation') or {}
    require(preparation.get('readOnlyRequests') == 130, 'Expected exactly130 read-only preparation requests.')
    barrier = preparation.get('barrier') or {}
    require(barrier.get('poolScope') == 'load' and barrier.get('passed') is True, 'A load-pool physical connection barrier was not established.')
    for name in ('targetConnections', 'heldResponses', 'nonemptyHttp11Responses', 'tlsConnectionsAtBarrier'):
        require(barrier.get(name) == 128, 'Physical connection barrier count differs: ' + name)
    preflight = report.get('preflight') or {}
    require(preflight.get('offered') == OFFERED, 'Incomplete offered count.')
    require(isinstance(preflight.get('correct'), int) and isinstance(preflight.get('errors'), int), 'Invalid preflight counters.')
    require(preflight['correct'] + preflight['errors'] == OFFERED and 0 <= preflight.get('dropped', -1) <= preflight['errors'], 'Preflight success/error accounting differs.')
    require(isinstance(report.get('state'), dict) and isinstance(report['state'].get('passed'), bool), 'Missing final-state validation.')
    if status == 'passed':
        require(preflight['correct'] == OFFERED and preflight['errors'] == preflight['dropped'] == 0 and report['state']['passed'], 'A passing preflight contains unsuccessful work or state mismatch.')
    else:
        require(preflight['errors'] > 0 or preflight['dropped'] > 0 or not report['state']['passed'], 'Failure status has no reported failure.')
        validate_preflight_rejection(directory, RATE, transport)

    require(report.get('plannedManifestOffers') == PLANNED_MANIFEST, 'Probe did not retain the canonical360000-offer manifest/preconditioning.')
    require(report.get('telemetryFile') == 'preflight-evidence-accounting.json', 'Unsupported phase telemetry reference.')
    prepared = validate_collector_preparation(directory)
    accounting = validate_phase_telemetry(directory, 'preflight')
    require(prepared['readOnlyRequests'] == preparation['readOnlyRequests'] and prepared['successfulReadOnlyRequests'] == preparation.get('successfulReadOnlyRequests') and prepared['barrier'] == preparation['barrier'], 'Preparation metadata and result disagree.')
    require(accounting['offeredCount'] == accounting['observedCount'] == OFFERED, 'Probe phase metadata is not exactly4000 actual offers.')
    legacy = read_json(directory / 'collector-preflight.json')
    require(legacy.get('preflight') == preflight and legacy.get('state') == report['state'], 'Preflight result files disagree.')
    for filename in ('preflight-requests.jsonl.gz', 'offered-manifest.jsonl.gz'):
        path = directory / filename
        require(path.is_file() and path.stat().st_size > 0, 'Required raw evidence is absent: ' + filename)
    require(not any((directory / name).exists() for name in ('warmup-requests.jsonl.gz', 'measured-requests.jsonl.gz', 'load-result.json', 'warmup-result.json')), 'Probe unexpectedly entered warmup/measured load.')
    return report, {'actual_offers_accounted': OFFERED, 'planned_manifest_offers': PLANNED_MANIFEST, 'phase_accounting_complete': True, 'physical_barrier_metadata_validated': True, 'raw_audit': 'Deferred until the complete twelve-run matrix; no streaming during probe schedules.'}


def audit_raw_after_matrix(output):
    """Stream all raw evidence only after every planned probe has finished."""
    audits = []
    for directory in sorted((output / 'probes').glob('*/*/driver')):
        report = read_json(directory / 'preflight-result.json')
        accounting = read_json(directory / 'preflight-evidence-accounting.json')
        frequency, started, joined = (accounting[name] for name in ('stopwatchFrequency', 'phaseStartedTicks', 'requestsCompletedTicks'))
        errors = {}
        raw_correct = raw_dropped = 0
        prefix = []
        with gzip.open(directory / 'preflight-requests.jsonl.gz', 'rt', encoding='utf-8') as stream:
            header = json.loads(next(stream))
            columns = header.get('columns', [])
            require(header.get('schema') == 1 and header.get('frequency') == frequency and len(set(columns)) == len(columns), 'Unsupported raw offered-record schema.')
            require({'index', 'operation', 'scheduledTicks', 'sentTicks', 'completedTicks', 'httpStatus', 'bodyBytes', 'error'}.issubset(columns), 'Raw offered-record columns are incomplete.')
            count = 0
            for count, line in enumerate(stream, 1):
                values = json.loads(line)
                require(isinstance(values, list) and len(values) == len(columns), 'Malformed offered record.')
                row = dict(zip(columns, values))
                require(row['index'] == count - 1 and row['scheduledTicks'] == started + (count - 1) * frequency // RATE, 'Missing/reordered offered index or changed schedule.')
                require(row['scheduledTicks'] <= row['completedTicks'] <= joined, 'Offered completion lies outside phase accounting.')
                require(isinstance(row['error'], str), 'Invalid offered error representation.')
                prefix.append((row['index'], row['operation']))
                if row['error']:
                    errors[row['error']] = errors.get(row['error'], 0) + 1
                    if row['error'] == 'offered.dropped':
                        raw_dropped += 1
                        require(row['sentTicks'] == 0, 'Dropped offered work was marked sent.')
                else:
                    raw_correct += 1
                    require(row['httpStatus'] == 200 and row['bodyBytes'] > 0 and row['sentTicks'] >= row['scheduledTicks'], 'Successful offered record has invalid HTTP/body/send evidence.')
            require(count == OFFERED, 'Raw offered-record count is not4000.')
        manifest_count = 0
        with gzip.open(directory / 'offered-manifest.jsonl.gz', 'rt', encoding='utf-8') as stream:
            for manifest_count, line in enumerate(stream, 1):
                item = json.loads(line)
                require(item.get('index') == manifest_count - 1, 'Planned manifest has missing/reordered indices.')
                if manifest_count <= OFFERED:
                    require(prefix[manifest_count - 1] == (item['index'], item['operation']), 'Actual index/operation prefix differs from frozen planned manifest.')
            require(manifest_count == PLANNED_MANIFEST, 'Full planned manifest was truncated; expected360000 rows.')
        preflight = report['preflight']
        require(raw_correct == preflight['correct'] and raw_dropped == preflight['dropped'] and errors == preflight.get('errorKinds'), 'Raw and structured preflight accounting disagree.')
        audits.append({'directory': directory.relative_to(output).as_posix(), 'actual_offered_rows': OFFERED, 'planned_manifest_rows': manifest_count, 'index_operation_prefix_matches': True, 'correct': raw_correct, 'dropped': raw_dropped, 'error_kinds': errors, 'payload_boundary': 'Raw request records retain index/operation/timestamps/status/bytes/error, not complete wire payloads; driver business/state validation remains separately retained.'})
    require(len(audits) == 12, 'Raw post-matrix audit did not cover twelve declared probes.')
    write_json(output / 'post-matrix-raw-audit.json', {'status': 'passed', 'actual_offered_rows': OFFERED * 12, 'planned_manifest_rows': PLANNED_MANIFEST * 12, 'audits': audits})
    return audits



class ProbeRunner(Runner):
    def run_driver(self, server, directory):
        directory.mkdir(parents=True, exist_ok=False)
        command = self.command(DRIVER_CPUS, '--load-client', '--preflight-only=true', '--url=' + server.ready['address'], '--ca-file=' + str(self.ca), '--transport=' + server.transport, '--output=' + str(directory), '--warmup=60', '--seconds=180', '--rate=2000')
        write_json(directory / 'invocation.json', {'command': command, 'observed_at_utc': stamp(), 'scope': 'Canonical rate2000/180s/60s manifest and preconditioning retained, then stop after exactly2s/4000 actual preflight offers; no warmup/measurement execution'})
        with (directory / 'stdout.txt').open('xb') as stdout, (directory / 'stderr.txt').open('xb') as stderr:
            process = subprocess.Popen(command, cwd=self.args.server_working_directory, env=self.environment, stdout=stdout, stderr=stderr, start_new_session=True)
            self.owned.append(process)
            deadline = time.monotonic() + 120
            try:
                while process.poll() is None:
                    if server.process.poll() is not None:
                        raise InfrastructureFailure('Owned server exited during collector probe.')
                    if time.monotonic() >= deadline:
                        raise InfrastructureFailure('Collector probe exceeded fixed120s timeout.')
                    self.progress.tick()
                    time.sleep(.1)
            finally:
                if process.poll() is None:
                    self.terminate(process)
        report, accounting = validate_result(directory, server.transport, process.returncode)
        return report, accounting, process.returncode

    def probe(self):
        observations = []
        for transport in ('http', 'graphql'):
            for repetition, order in enumerate(PAIR_ORDER):
                for letter in order:
                    variant = 'baseline' if letter == 'B' else 'engine'
                    directory = self.output / 'probes' / transport / f'{repetition:02d}-{variant}'
                    self.progress.update(phase='collector-preflight-probe', transport=transport, repetition=repetition, variant=variant)
                    with Server(self, directory, variant, transport) as server:
                        report, accounting, exit_code = self.run_driver(server, directory / 'driver')
                    observation = {'transport': transport, 'repetition': repetition, 'pair_order': order, 'variant': variant, 'status': report['status'], 'driver_exit_code': exit_code, 'preparation': report['preparation'], 'preflight': report['preflight'], 'state': report['state'], 'raw_accounting': accounting, 'shutdown': server.shutdown, 'timed_warmup_or_measurement_executed': False, 'performance_gate': 'Not scored; bounded collector readiness/capacity diagnosis only'}
                    write_json(directory / 'observation.json', observation)
                    observations.append(observation)
                    write_json(self.output / 'probe-observations.json', observations)
                    require(server.shutdown['passed'], 'Owned server shutdown/probe/lifetime validation failed.')
        require(len(observations) == 12, 'Planned twelve-run matrix is incomplete.')
        return observations


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--dotnet', required=True, type=Path)
    parser.add_argument('--assembly', required=True, type=Path)
    parser.add_argument('--engine-root', type=Path, default=ROOT.parent / 'Cehpalon-Engine')
    parser.add_argument('--server-working-directory', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    if sys.platform != 'linux':
        parser.error('This frozen observation requires Linux; #3 Windows qualification remains separate.')
    args.dotnet, args.assembly, args.engine_root = args.dotnet.resolve(), args.assembly.resolve(), args.engine_root.resolve()
    args.server_working_directory = args.server_working_directory.resolve()
    require(args.server_working_directory.is_dir(), 'Server working directory must exist.')
    args.phases = []
    output = (ROOT / args.output).resolve()
    private = (ROOT / '.local').resolve()
    native_private = (Path.home() / '.local/share/cehpalon-benchmark-runs').resolve()
    if not ((output.is_relative_to(private) and output != private) or (output.is_relative_to(native_private) and output != native_private)):
        parser.error('Use a fresh ignored Samples.local or task-owned Linux-home benchmark-runs directory.')
    if output.is_relative_to(native_private):
        native_private.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(native_private, 0o700)
    output.mkdir(parents=True, exist_ok=False)
    os.chmod(output, 0o700)
    runner = ProbeRunner(args, output)
    def interrupted(signum, frame):
        raise KeyboardInterrupt('Received signal; stop only owned probe processes.')
    signal.signal(signal.SIGTERM, interrupted)
    summary = {'started_at_utc': stamp(), 'scope': 'Twelve fresh-server collector preparation/preflight probes; not full benchmark or performance acceptance', 'classification': 'OBSERVATIONAL; nonqualifying reference environment', 'reference_gate_passed': False, 'planned_runs': 12}
    try:
        runner.preflight()
        runner.manifest['protocol'] = {'purpose': 'Equal physical load-pool TLS readiness diagnosis', 'transports_in_order': ['http', 'graphql'], 'pair_order': list(PAIR_ORDER), 'fresh_server_each_run': True, 'rate': RATE, 'seconds': SECONDS, 'offered_per_run': OFFERED, 'planned_manifest_offers': PLANNED_MANIFEST, 'planned_measured_seconds': PLANNED_MEASURED_SECONDS, 'planned_warmup_seconds': PLANNED_WARMUP_SECONDS, 'manifest_boundary': 'Full360000 planned offered manifest retained; only its first4000 requests execute in the preflight; planned warmup/measured phases do not execute', 'read_only_preparation_requests': 130, 'held_http11_responses': 128, 'physical_load_tls_connections_at_barrier': 128, 'warmup_executed': False, 'measured_load_executed': False, 'retry_policy': 'None: retain coherent failures and continue only the next declared run; incomplete evidence aborts the attempt'}
        runner.manifest['scope'] = summary['scope']
        write_json(output / 'manifest.json', runner.manifest)
        observations = runner.probe()
        raw_audits = audit_raw_after_matrix(output)
        failed = sum(item['status'] != 'passed' for item in observations)
        summary.update(status='probe-matrix-complete', completed_runs=len(observations), preflight_passed_runs=len(observations) - failed, coherent_preflight_failures=failed, actual_offered_records_audited=OFFERED * len(raw_audits), planned_manifest_records_audited=PLANNED_MANIFEST * len(raw_audits), warmup_or_measured_load_runs=0, all_lifetimes_passed=all(item['shutdown']['passed'] for item in observations), completed_at_utc=stamp())
        runner.manifest.update(status=summary['status'], completed_at_utc=summary['completed_at_utc'])
        write_json(output / 'manifest.json', runner.manifest)
        write_json(output / 'summary.json', summary)
        runner.progress.update(status=summary['status'], phase='complete', completed_runs=len(observations))
        print(json.dumps(summary))
        return 0  # Complete collection is separate from a successful preflight observation.
    except BaseException as error:
        summary.update(status='aborted-infrastructure', error=repr(error), completed_at_utc=stamp())
        runner.manifest.update(status=summary['status'], error=repr(error), completed_at_utc=summary['completed_at_utc'])
        write_json(output / 'manifest.json', runner.manifest)
        write_json(output / 'summary.json', summary)
        (output / 'failure-traceback.txt').write_text(traceback.format_exc(), encoding='utf-8')
        runner.progress.update(status=summary['status'], phase='aborted', error=repr(error))
        print(json.dumps(summary), file=sys.stderr)
        return 1
    finally:
        for process in reversed(runner.owned):
            runner.terminate(process)
        runner.progress.events.close()


if __name__ == '__main__':
    raise SystemExit(main())
