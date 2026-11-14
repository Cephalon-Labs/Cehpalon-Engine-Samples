"""Offline guards against false physical-readiness/phase telemetry claims."""
import copy
import json
from pathlib import Path
import tempfile
import unittest

from small_api_collector_evidence import (
    validate_collector_preparation, validate_phase_telemetry, validate_preflight_rejection,
)
from probe_small_api_collector import validate_result, InfrastructureFailure


def preparation():
    frequency, start, barrier_start = 1_000_000_000, 1_000_000_000, 1_000_001_000
    all_headers, released, end = barrier_start + 2000, barrier_start + 2010, barrier_start + 3010
    rows, tls = [], []
    for index in range(130):
        warm = index < 2
        began = start + index * 100 if warm else barrier_start + (index - 2) * 10
        headers = began + 20 if warm else began + 3
        read = headers + 1 if warm else released + 10 + index
        rows.append({'preparationIndex': index, 'index': index, 'operation': 'list' if index == 1 else 'get', 'stage': 'warm-read' if warm else 'held-load', 'pool': 'control' if warm else 'load', 'startedTicks': began, 'headersReadyTicks': headers, 'bodyReadStartedTicks': read, 'bodyCompletedTicks': read + 10, 'completedTicks': read + 20, 'connectionId': None if warm else index, 'status': 200, 'bytes': 120, 'error': None, 'httpVersion': '1.1', 'contentLength': 120 if index == 0 else None, 'chunked': index != 0, 'connectionClose': False, 'passed': True})
        if not warm:
            tls.append({'connectionId': index, 'pool': 'load', 'protocol': 'Tls13', 'cipher': 'TLS_AES_256_GCM_SHA384', 'httpVersion': '1.1', 'connectedTicks': began + 1, 'stopwatchFrequency': frequency, 'preparationIndex': index})
    tls.insert(0, {'connectionId': 1, 'pool': 'control', 'protocol': 'Tls13', 'cipher': 'TLS_AES_256_GCM_SHA384', 'httpVersion': '1.1', 'connectedTicks': start + 1, 'stopwatchFrequency': frequency, 'preparationIndex': None})
    return {'schemaVersion': 1, 'status': 'passed', 'readOnlyRequests': 130, 'successfulReadOnlyRequests': 130, 'requests': rows, 'barrier': {'targetConnections': 128, 'poolScope': 'load', 'heldResponses': 128, 'nonemptyHttp11Responses': 128, 'tlsConnectionsAtBarrier': 128, 'distinctConnectionCount': 128, 'distinctConnectionIds': list(range(2, 130)), 'loadTlsConnectionIdsAtBarrier': list(range(2, 130)), 'startedTicks': barrier_start, 'allHeadersReadyTicks': all_headers, 'releasedTicks': released, 'completedTicks': end, 'deadlineSeconds': 30, 'passed': True}, 'clientBefore': {'observedTicks': start - 1}, 'clientAfter': {'observedTicks': end + 100}, 'tlsConnections': tls, 'preparationStartedTicks': start, 'preparationCompletedTicks': end + 100, 'stopwatchFrequency': frequency, 'error': None}


def phase(prepared, name='preflight'):
    frequency, start = prepared['stopwatchFrequency'], prepared['preparationCompletedTicks'] + 10_000
    joined = start + 2 * frequency
    return {'telemetrySchemaVersion': 1, 'phase': name, 'offeredCount': 4000, 'observedCount': 4000, 'phaseStartedTicks': start, 'requestsCompletedTicks': joined, 'clientBefore': {'observedTicks': start - 10}, 'clientAfter': {'observedTicks': joined + 10}, 'completionMetricsStartedTicks': joined + 20 if name == 'measured' else None, 'completionMetricsCompletedTicks': joined + 40 if name == 'measured' else None, 'persistenceStartedTicks': joined + 100, 'persistenceCompletedTicks': joined + 200, 'stopwatchFrequency': frequency, 'phaseFailure': None, 'tlsConnectionsBefore': copy.deepcopy(prepared['tlsConnections']), 'tlsConnectionsAfter': copy.deepcopy(prepared['tlsConnections']), 'newTlsConnectionIds': []}


class CollectorEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='cehpalon-metadata-test-')
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.prepared = preparation()

    def write(self, name, value):
        (self.directory / name).write_text(json.dumps(value), encoding='utf-8')

    def check_preparation(self, mutate=None):
        value = copy.deepcopy(self.prepared)
        if mutate:
            mutate(value)
        self.write('collector-preparation.json', value)
        return validate_collector_preparation(self.directory)

    def check_phase(self, mutate=None, name='preflight'):
        self.write('collector-preparation.json', self.prepared)
        value = phase(self.prepared, name)
        if mutate:
            mutate(value)
        self.write(name + '-evidence-accounting.json', value)
        (self.directory / (name + '-requests.jsonl.gz')).write_bytes(b'metadata-only fixture; not a raw stream audit')
        return validate_phase_telemetry(self.directory, name)

    def test_complete_held_connection_evidence(self):
        self.assertEqual(self.check_preparation()['barrier']['distinctConnectionCount'], 128)

    def test_duplicate_physical_lease_rejected(self):
        with self.assertRaises(ValueError):
            self.check_preparation(lambda x: x['requests'][3].update(connectionId=2))

    def test_body_read_before_common_release_rejected(self):
        with self.assertRaises(ValueError):
            self.check_preparation(lambda x: x['requests'][2].update(bodyReadStartedTicks=x['barrier']['releasedTicks'] - 1))

    def test_wrong_first_use_request_binding_rejected(self):
        with self.assertRaises(ValueError):
            self.check_preparation(lambda x: x['tlsConnections'][1].update(preparationIndex=3))

    def test_http2_multiplexing_does_not_count_as_http11_leases(self):
        with self.assertRaises(ValueError):
            self.check_preparation(lambda x: x['requests'][2].update(httpVersion='2.0'))

    def test_empty_and_close_delimited_responses_rejected(self):
        for changes in ({'bytes': 0}, {'contentLength': 0}, {'contentLength': None, 'chunked': False}, {'connectionClose': True}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                self.check_preparation(lambda x: x['requests'][2].update(changes))

    def test_full_shared_preparation_deadline_not_only_barrier(self):
        with self.assertRaises(ValueError):
            self.check_preparation(lambda x: x.update(preparationStartedTicks=x['preparationStartedTicks'] - 31 * x['stopwatchFrequency']))

    def test_missing_or_duplicate_preparation_identity_rejected(self):
        for mutate in (lambda x: x['requests'].pop(), lambda x: x['requests'][3].update(preparationIndex=2)):
            with self.assertRaises(ValueError):
                self.check_preparation(mutate)

    def test_wrong_load_pool_or_unobserved_identity_rejected(self):
        for mutate in (lambda x: x['barrier'].update(poolScope='control'), lambda x: x['barrier']['loadTlsConnectionIdsAtBarrier'].__setitem__(0, 900)):
            with self.assertRaises(ValueError):
                self.check_preparation(mutate)

    def test_preparation_requires_actual_tls13_metadata(self):
        with self.assertRaises(ValueError):
            self.check_preparation(lambda x: x['tlsConnections'][1].update(protocol='Tls12'))

    def test_all_three_phase_boundaries(self):
        for name in ('preflight', 'warmup', 'measured'):
            with self.subTest(phase=name):
                self.assertEqual(self.check_phase(name=name)['phase'], name)

    def test_missing_offered_observations_rejected(self):
        with self.assertRaises(ValueError):
            self.check_phase(lambda x: x.update(observedCount=3999))

    def test_phase_requires_nonempty_raw_evidence_artifact(self):
        self.check_phase()
        raw = self.directory / 'preflight-requests.jsonl.gz'
        raw.unlink()
        with self.assertRaises(ValueError):
            validate_phase_telemetry(self.directory, 'preflight')
        raw.write_bytes(b'')
        with self.assertRaises(ValueError):
            validate_phase_telemetry(self.directory, 'preflight')

    def test_client_metrics_must_bracket_schedule_and_join(self):
        changes = [lambda x: x['clientBefore'].update(observedTicks=x['phaseStartedTicks'] + 1), lambda x: x['clientAfter'].update(observedTicks=x['requestsCompletedTicks'] - 1), lambda x: x['clientAfter'].update(observedTicks=x['persistenceStartedTicks'] + 1)]
        for mutate in changes:
            with self.assertRaises(ValueError):
                self.check_phase(mutate)

    def test_connection_history_cannot_be_rewritten(self):
        with self.assertRaises(ValueError):
            self.check_phase(lambda x: x['tlsConnectionsAfter'][1].update(connectedTicks=1))

    def test_cumulative_count_is_not_a_substitute_for_prepared_identities(self):
        def replace_history(value):
            for name in ('tlsConnectionsBefore', 'tlsConnectionsAfter'):
                value[name][1]['connectionId'] = 500
        with self.assertRaises(ValueError):
            self.check_phase(replace_history)

    def test_new_connection_delta_must_match_retained_events(self):
        with self.assertRaises(ValueError):
            self.check_phase(lambda x: x.update(newTlsConnectionIds=[500]))

    def test_new_postjoin_background_event_retained_without_live_pool_claim(self):
        def add(value):
            event = dict(value['tlsConnectionsAfter'][1], connectionId=500, preparationIndex=None, connectedTicks=value['requestsCompletedTicks'] + 1)
            value['tlsConnectionsAfter'].append(event)
            value['newTlsConnectionIds'] = [500]
        self.assertEqual(self.check_phase(add)['newTlsConnectionIds'], [500])

    def test_measured_metrics_cannot_follow_raw_persistence(self):
        with self.assertRaises(ValueError):
            self.check_phase(lambda x: x.update(completionMetricsCompletedTicks=x['persistenceStartedTicks'] + 1), name='measured')

    def test_phase_implementation_fault_is_not_coherent_capacity_result(self):
        with self.assertRaises(ValueError):
            self.check_phase(lambda x: x.update(phaseFailure='fixture implementation failure'))

    def test_missing_metadata_fails_closed(self):
        with self.assertRaises(ValueError):
            validate_collector_preparation(self.directory)

    def rejection(self):
        self.write('collector-preparation.json', self.prepared)
        telemetry = phase(self.prepared)
        self.write('preflight-evidence-accounting.json', telemetry)
        (self.directory / 'preflight-requests.jsonl.gz').write_bytes(b'metadata-only fixture; not a raw stream audit')
        counts = {'offered': 4000, 'correct': 3963, 'errors': 37, 'dropped': 37, 'successfulWithinDrain': 3963, 'p95Ms': 1.7, 'p99Ms': 70.1, 'errorKinds': {'offered.dropped': 37}}
        fields = {'status': 'collector-preflight-failed', 'enteredPhases': ['preflight'], 'warmupEntered': False, 'measuredEntered': False, 'telemetryFile': 'preflight-evidence-accounting.json'}
        preflight = dict(fields, schemaVersion=1, preflight=counts, state={'passed': True, 'reason': ''})
        failure = dict(fields, schemaVersion=1, stage='preflight', transport='http', rate=2000, error='Known completed preflight guard', stopwatchFrequency=telemetry['stopwatchFrequency'], preparationFile='collector-preparation.json', reportFile='collector-preflight.json', counts=copy.deepcopy(counts), tlsConnections=copy.deepcopy(telemetry['tlsConnectionsAfter']), client={'observedTicks': telemetry['persistenceCompletedTicks'] + 10}, observedTicks=telemetry['persistenceCompletedTicks'] + 20)
        self.write('collector-preflight.json', preflight)
        self.write('collector-failure.json', failure)
        return preflight, failure, telemetry

    def test_completed_known_preflight_rejection_retained(self):
        self.rejection()
        self.assertEqual(validate_preflight_rejection(self.directory, 2000, 'http')['counts']['dropped'], 37)

    def test_unknown_preflight_report_schema_rejected(self):
        preflight, _, _ = self.rejection()
        preflight['schemaVersion'] = 99
        self.write('collector-preflight.json', preflight)
        with self.assertRaises(ValueError):
            validate_preflight_rejection(self.directory, 2000, 'http')

    def test_phase_and_preparation_crashes_are_not_preflight_guards(self):
        for status, stage in [('collector-phase-failed', 'preflight'), ('preparation-failed', 'preparation')]:
            _, failure, _ = self.rejection()
            failure.update(status=status, stage=stage)
            self.write('collector-failure.json', failure)
            with self.assertRaises(ValueError):
                validate_preflight_rejection(self.directory, 2000, 'http')

    def test_rejection_cannot_hide_later_phase_or_artifacts(self):
        for filename in ('warmup-requests.jsonl.gz', 'measured-evidence-accounting.json', 'load-result.json', 'warmup-result.json'):
            self.rejection()
            artifact = self.directory / filename
            artifact.write_text('unrelated later phase')
            with self.assertRaises(ValueError):
                validate_preflight_rejection(self.directory, 2000, 'http')
            artifact.unlink()

    def test_rejection_counters_and_references_must_match(self):
        changes = [lambda x: x['counts'].update(p95Ms=999), lambda x: x.update(reportFile='another-report.json'), lambda x: x.update(telemetryFile='measured-evidence-accounting.json'), lambda x: x.update(enteredPhases=['preflight', 'warmup'])]
        for mutate in changes:
            _, failure, _ = self.rejection()
            mutate(failure)
            self.write('collector-failure.json', failure)
            with self.assertRaises(ValueError):
                validate_preflight_rejection(self.directory, 2000, 'http')

    def test_failure_must_preserve_after_phase_tls_history(self):
        _, failure, _ = self.rejection()
        failure['tlsConnections'].pop()
        self.write('collector-failure.json', failure)
        with self.assertRaises(ValueError):
            validate_preflight_rejection(self.directory, 2000, 'http')

    def test_failure_snapshot_uses_matching_monotonic_boundary(self):
        _, failure, telemetry = self.rejection()
        failure['client']['observedTicks'] = telemetry['requestsCompletedTicks'] - 1
        self.write('collector-failure.json', failure)
        with self.assertRaises(ValueError):
            validate_preflight_rejection(self.directory, 2000, 'http')

    def test_probe_rejects_arbitrary_abort_even_with_a_guard_status_file(self):
        self.write('preflight-result.json', {'schemaVersion': 1, 'mode': 'preflight-only', 'transport': 'http', 'rate': 2000, 'offeredCount': 4000, 'seconds': 2, 'status': 'collector-preflight-failed'})
        with self.assertRaises(InfrastructureFailure):
            validate_result(self.directory, 'http', -6)


if __name__ == '__main__':
    unittest.main()
