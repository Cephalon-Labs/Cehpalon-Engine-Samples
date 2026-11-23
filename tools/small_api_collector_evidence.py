"""Metadata-only collector evidence guards shared by probes and full runs.

These guards establish the declared preparation/phase boundaries. They do not
stream offered-record gzip files, infer an acceptance pass or retry a failure.
Full raw-record/manifest audits belong after the complete experiment.
"""
import gzip
import json
from pathlib import Path


def require(condition, message):
    if not condition:
        raise ValueError(message)


def read_json(path):
    try:
        result = json.loads(Path(path).read_text(encoding='utf-8'))
    except (OSError, ValueError) as error:
        raise ValueError('Missing/incomplete collector metadata: ' + str(path)) from error
    require(isinstance(result, dict), 'Collector metadata must be an object: ' + str(path))
    return result


def integer(value):
    return isinstance(value, int) and not isinstance(value, bool)


def tls_by_id(rows, frequency):
    require(isinstance(rows, list), 'TLS telemetry must be an array.')
    result = {}
    for row in rows:
        require(isinstance(row, dict), 'TLS event must be an object.')
        identifier = row.get('connectionId')
        require(integer(identifier) and identifier > 0 and identifier not in result, 'Missing/duplicate physical TLS connection identity.')
        require(row.get('pool') in ('control', 'load'), 'TLS event has an unknown pool.')
        require(row.get('protocol') == 'Tls13' and row.get('httpVersion') == '1.1' and isinstance(row.get('cipher'), str) and row['cipher'], 'Actual TLS1.3/HTTP1.1 metadata is missing.')
        require(row.get('stopwatchFrequency') == frequency and integer(row.get('connectedTicks')) and row['connectedTicks'] > 0, 'TLS event clock differs from collector clock.')
        result[identifier] = row
    return result


def validate_collector_preparation(directory):
    """Require130 successful reads and128 physically distinct held load leases."""
    directory = Path(directory)
    report = read_json(directory / 'collector-preparation.json')
    require(report.get('schemaVersion') == 1 and report.get('status') == 'passed' and report.get('error') is None, 'Collector preparation did not complete successfully.')
    require(report.get('readOnlyRequests') == report.get('successfulReadOnlyRequests') == 130, 'Preparation must contain exactly130 successful read-only requests.')
    rows = report.get('requests')
    require(isinstance(rows, list) and len(rows) == 130, 'Preparation request metadata is incomplete.')
    require(all(isinstance(row, dict) and integer(row.get('preparationIndex')) for row in rows), 'Preparation request identities are not integers.')
    require({row.get('preparationIndex') for row in rows} == set(range(130)), 'Preparation identities are missing/duplicated.')
    frequency = report.get('stopwatchFrequency')
    started, completed = report.get('preparationStartedTicks'), report.get('preparationCompletedTicks')
    require(integer(frequency) and frequency > 0 and integer(started) and integer(completed) and started < completed, 'Invalid preparation clock boundary.')
    require(isinstance(report.get('clientBefore'), dict) and isinstance(report.get('clientAfter'), dict), 'Preparation client telemetry is missing.')
    barrier = report.get('barrier') or {}
    require(isinstance(barrier, dict), 'Physical readiness barrier must be an object.')
    require(barrier.get('passed') is True and barrier.get('poolScope') == 'load' and barrier.get('deadlineSeconds') == 30, 'Physical load-pool barrier is missing or changed.')
    for name in ('targetConnections', 'heldResponses', 'nonemptyHttp11Responses', 'tlsConnectionsAtBarrier', 'distinctConnectionCount'):
        require(barrier.get(name) == 128, 'Physical readiness count differs: ' + name)
    begin, headers, released, end = [barrier.get(name) for name in ('startedTicks', 'allHeadersReadyTicks', 'releasedTicks', 'completedTicks')]
    require(all(integer(tick) for tick in (begin, headers, released, end)) and started <= begin <= headers <= released <= end <= completed, 'Barrier clock ordering is invalid.')
    require(end - started <= 30 * frequency, 'Shared preparation/reset/warm/barrier work exceeded its fixed30s deadline.')
    tls = tls_by_id(report.get('tlsConnections'), frequency)
    require(all(event['connectedTicks'] <= completed for event in tls.values()), 'Preparation TLS event lies after preparation completion.')
    held_ids = set()
    held_count = warm_count = 0
    for row in rows:
        require(row.get('passed') is True and row.get('status') == 200 and integer(row.get('bytes')) and row['bytes'] > 0 and row.get('error') is None, 'Preparation contains an invalid response.')
        require(row.get('operation') in ('get', 'list') and row.get('httpVersion') == '1.1' and row.get('connectionClose') is False, 'Preparation changed the read-only HTTP1.1 keep-alive contract.')
        length = row.get('contentLength')
        require((integer(length) and length > 0) or (length is None and row.get('chunked') is True), 'Preparation response does not have nonempty persistent body framing.')
        ticks = [row.get(name) for name in ('startedTicks', 'headersReadyTicks', 'bodyReadStartedTicks', 'bodyCompletedTicks', 'completedTicks')]
        require(all(integer(tick) for tick in ticks) and started <= ticks[0] <= ticks[1] <= ticks[2] <= ticks[3] <= ticks[4] <= completed, 'Preparation response clock ordering is invalid.')
        if row.get('stage') == 'warm-read':
            warm_count += 1
            require(row['preparationIndex'] in (0, 1) and row.get('pool') == 'control' and ticks[-1] <= begin, 'Warm reads are not complete before the load barrier.')
        else:
            held_count += 1
            require(row.get('stage') == 'held-load' and row['preparationIndex'] in range(2, 130) and row.get('pool') == 'load', 'Unknown preparation request stage/pool.')
            identifier = row.get('connectionId')
            require(integer(identifier) and identifier not in held_ids and identifier in tls, 'Held responses are not128 distinct observed physical TLS connections.')
            event = tls[identifier]
            require(event['pool'] == 'load' and event.get('preparationIndex') == row['preparationIndex'], 'Held response is not bound to its first-use load TLS connection.')
            require(begin <= ticks[0] <= event['connectedTicks'] <= ticks[1] <= headers and released <= ticks[2] and ticks[-1] <= end, 'A held body was read before common release or connection/header order differs.')
            held_ids.add(identifier)
    require(warm_count == 2 and held_count == 128, 'Preparation stage counts differ from2+128.')
    for name in ('distinctConnectionIds', 'loadTlsConnectionIdsAtBarrier'):
        identifiers = barrier.get(name)
        require(isinstance(identifiers, list) and all(integer(value) for value in identifiers), 'Barrier connection identity array is invalid: ' + name)
        require(len(identifiers) == len(set(identifiers)) == 128 and set(identifiers) == held_ids, 'Barrier physical connection identity set differs: ' + name)
    observed_load_ids = {identifier for identifier, event in tls.items() if event['pool'] == 'load' and event['connectedTicks'] <= headers}
    require(observed_load_ids == held_ids, 'Load TLS connection count/identity at readiness differs from held leases.')
    return report


def validate_phase_telemetry(directory, phase):
    """Require complete post-join TLS/client evidence, including failed phases."""
    require(phase in ('preflight', 'warmup', 'measured'), 'Unknown collector phase.')
    directory = Path(directory)
    report = read_json(directory / (phase + '-evidence-accounting.json'))
    raw = directory / (phase + '-requests.jsonl.gz')
    try:
        raw_present = raw.is_file() and raw.stat().st_size > 0
    except OSError as error:
        raise ValueError('Phase raw evidence cannot be observed: ' + str(raw)) from error
    require(raw_present, 'Phase raw evidence is missing or empty; metadata alone is insufficient.')
    require(report.get('telemetrySchemaVersion') == 1 and report.get('phase') == phase, 'Unsupported phase telemetry schema.')
    offered, observed = report.get('offeredCount'), report.get('observedCount')
    require(integer(offered) and offered > 0 and observed == offered, 'Phase metadata does not account for every offered request.')
    require(report.get('phaseFailure') is None, 'A phase implementation failure requires an invalid-attempt audit.')
    frequency = report.get('stopwatchFrequency')
    begin, joined, persistence = [report.get(name) for name in ('phaseStartedTicks', 'requestsCompletedTicks', 'persistenceStartedTicks')]
    require(integer(frequency) and frequency > 0 and all(integer(tick) for tick in (begin, joined, persistence)) and begin < joined <= persistence, 'Invalid request-join/persistence clock boundary.')
    require(isinstance(report.get('clientBefore'), dict) and isinstance(report.get('clientAfter'), dict), 'Phase client telemetry is missing.')
    client_begin, client_end = report['clientBefore'].get('observedTicks'), report['clientAfter'].get('observedTicks')
    require(integer(client_begin) and integer(client_end) and client_begin <= begin < joined <= client_end <= persistence, 'Client metrics do not bracket request scheduling/join before persistence.')
    before = tls_by_id(report.get('tlsConnectionsBefore'), frequency)
    after = tls_by_id(report.get('tlsConnectionsAfter'), frequency)
    require(set(before).issubset(after), 'Physical TLS history was lost across a phase.')
    require(all(event['connectedTicks'] <= begin for event in before.values()) and all(event['connectedTicks'] <= persistence for event in after.values()), 'Phase TLS events lie outside the retained snapshot/persistence boundaries.')
    require(all(before[identifier] == after[identifier] for identifier in before), 'A physical connection identity was rewritten across the phase.')
    new = report.get('newTlsConnectionIds')
    require(isinstance(new, list) and all(integer(value) for value in new), 'New phase TLS identities are invalid.')
    require(len(new) == len(set(new)) and set(new) == set(after) - set(before), 'New phase TLS identities do not match retained snapshots.')
    preparation = validate_collector_preparation(directory)
    prepared_tls = tls_by_id(preparation['tlsConnections'], frequency)
    prepared_ids = set(preparation['barrier']['distinctConnectionIds'])
    require(prepared_ids.issubset(before) and all(before[identifier] == prepared_tls[identifier] for identifier in prepared_ids), 'Phase TLS history does not retain the unchanged128 prepared load identities; history is not a live-connection count.')
    if phase == 'measured':
        metric_begin, metric_end = report.get('completionMetricsStartedTicks'), report.get('completionMetricsCompletedTicks')
        require(integer(metric_begin) and integer(metric_end) and joined <= metric_begin <= metric_end <= persistence, 'Final metrics were not captured after join and before persistence.')
    return report


def validate_preflight_rejection(directory, rate, transport):
    """Accept only the documented completed-preflight guard, never a crash.

    The caller must separately require the managed guard's exit code1. This
    metadata-only function cannot infer a process exit status from files.
    """
    require(integer(rate) and rate > 0 and transport in ('http', 'graphql'), 'Invalid preflight rejection identity.')
    directory = Path(directory)
    validate_collector_preparation(directory)
    phase = validate_phase_telemetry(directory, 'preflight')
    preflight = read_json(directory / 'collector-preflight.json')
    failure = read_json(directory / 'collector-failure.json')
    require(preflight.get('schemaVersion') == 1 and preflight.get('status') == failure.get('status') == 'collector-preflight-failed', 'Only schema1 completed collector-preflight rejections are supported.')
    require(failure.get('schemaVersion') == 1 and failure.get('stage') == 'preflight' and failure.get('rate') == rate and failure.get('transport') == transport, 'Preflight rejection identity/schema differs.')
    for report in (preflight, failure):
        require(report.get('enteredPhases') == ['preflight'] and report.get('warmupEntered') is False and report.get('measuredEntered') is False, 'A rejection entered later workload phases.')
        require(report.get('telemetryFile') == 'preflight-evidence-accounting.json', 'Rejection phase-telemetry reference differs.')
    require(failure.get('preparationFile') == 'collector-preparation.json' and failure.get('reportFile') == 'collector-preflight.json', 'Rejection evidence references differ.')
    counts = preflight.get('preflight')
    require(isinstance(counts, dict) and counts.get('offered') == phase['offeredCount'] == rate * 2, 'Rejected preflight has the wrong offered count.')
    require(failure.get('counts') == counts, 'Rejected preflight/failure PhaseResult counters differ.')
    state = preflight.get('state')
    require(isinstance(state, dict) and isinstance(state.get('passed'), bool), 'Rejected preflight lacks final-state validation.')
    require((integer(counts.get('errors')) and counts['errors'] > 0) or (integer(counts.get('dropped')) and counts['dropped'] > 0) or not state['passed'], 'Rejection contains no documented numeric/state failure.')
    frequency = phase['stopwatchFrequency']
    require(failure.get('stopwatchFrequency') == frequency, 'Failure and phase clocks differ.')
    observed = failure.get('observedTicks')
    client = failure.get('client')
    require(integer(observed) and isinstance(client, dict) and integer(client.get('observedTicks')) and phase['requestsCompletedTicks'] <= client['observedTicks'] <= observed, 'Failure client/TLS snapshot boundary is invalid.')
    after = tls_by_id(phase['tlsConnectionsAfter'], frequency)
    retained = tls_by_id(failure.get('tlsConnections'), frequency)
    require(set(after).issubset(retained) and all(after[identifier] == retained[identifier] for identifier in after), 'Failure evidence lost/rewrote the after-phase physical TLS history.')
    require(all(event['connectedTicks'] <= observed for event in retained.values()), 'Failure TLS history lies after its observation boundary.')
    forbidden = []
    for pattern in ('warmup-*', 'measured-*'):
        forbidden.extend(path.name for path in directory.glob(pattern))
    forbidden.extend(name for name in ('load-result.json', 'warmup-result.json') if (directory / name).exists())
    require(not forbidden, 'A rejected preflight has evidence of later warmup/measurement: ' + ', '.join(sorted(set(forbidden))))
    return failure



def audit_successful_preflight_rows(directory, rate):
    """Reconcile successful remote raw observations with their full planned prefix."""
    directory = Path(directory)
    expected = rate * 2
    context = read_json(directory / 'preflight-evidence-accounting.json')
    frequency = context['stopwatchFrequency']
    started, joined = context['phaseStartedTicks'], context['requestsCompletedTicks']
    prefix = []
    with gzip.open(directory / 'preflight-requests.jsonl.gz', 'rt', encoding='utf-8') as stream:
        header = json.loads(next(stream))
        columns = header['columns']
        required = {'index', 'operation', 'scheduledTicks', 'sentTicks', 'completedTicks', 'httpStatus', 'bodyBytes', 'error'}
        require(header.get('schema') == 1 and header.get('frequency') == frequency
                and len(set(columns)) == len(columns) and required.issubset(columns), 'Unexpected raw preflight schema.')
        for index, line in enumerate(stream):
            values = json.loads(line)
            require(index < expected and isinstance(values, list) and len(values) == len(columns), 'Malformed or extra raw preflight row.')
            row = dict(zip(columns, values))
            require(row['index'] == index and row['scheduledTicks'] == started + index * frequency // rate,
                    'Raw preflight offered schedule differs.')
            require(row['scheduledTicks'] <= row['sentTicks'] <= row['completedTicks'] <= joined
                    and row['httpStatus'] == 200 and row['bodyBytes'] > 0 and row['error'] == '',
                    'Raw preflight does not show contract-valid responses.')
            prefix.append(row['operation'])
    require(len(prefix) == expected, 'Raw preflight offers are incomplete.')
    planned = 0
    with gzip.open(directory / 'offered-manifest.jsonl.gz', 'rt', encoding='utf-8') as stream:
        for planned, line in enumerate(stream, 1):
            row = json.loads(line)
            require(row.get('index') == planned - 1, 'Malformed ordered manifest.')
            if planned <= expected:
                require(row.get('operation') == prefix[planned - 1], 'Executed operations differ from the planned prefix.')
    require(planned == rate * 180, 'Planned preflight manifest is incomplete.')
    return {'actual_offers': len(prefix), 'planned_offers': planned, 'ordered_prefix_matches': True}
