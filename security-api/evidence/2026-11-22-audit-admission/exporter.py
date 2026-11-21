"""Root-only evidence export after all SDK lanes stop; no builds, runtime or remote writes.

Required: --consumer-revision FULL_SHA. Optional --config JSON can supply
driver_script, latest_source_freeze, expected_freeze_inputs, expected_source_union,
review, cleanup, hosted_ci_baseline, host_revision and the additive lists
extra_attempts / extra_declarations / extra_files. Each list entry contains path
and archive; extra source-freeze attempts may additionally declare kind=source-freeze,
matches_final=false, and consumer_revision when their frozen source was committed.
host_final_correction may record a reason and retained declaration archive when a
later consumer correction legitimately differs from the source-only host commit.
All default first attempts and declaration01 remain retained. Corrections are added,
never substituted for failed attempts. This helper records actual statuses and does
not assert that development/preparation was failure-free.

Read-only git show verifies explicit local commit blobs. No Git mutations, SDK,
container, cleanup, billing or network actions. Root separately reviews publication
privacy, SHA256SUMS and index bytes before committing the resulting archive.
"""
from pathlib import Path, PurePosixPath
import argparse
import hashlib
import json
import os
import re
import subprocess

B = Path('D:/Cephalon')
D = B / 'Cehpalon-Engine-Docs'
E = B / '.worktrees/arh-engine'
EW = E / '.local/arh-wsl-source01'
S = B / '.worktrees/ara-consumer'
SW = B / '.worktrees/ara-wsl-consumer'
HOST = B / '.worktrees/ara-host'
OUT = B / 'Cehpalon-Engine-Samples/security-api/evidence/2026-11-22-audit-admission'
ENGINE = '5184517a92a087abe4e0091d256142b6c35a2b39'
BASELINE = '05f119e75bcc2458bee9c610e4ba64f04d4dc6d0'
HOST_REVISION = '255f75f2a6dc0642a83c9009972b8f849bbc8dcc'
SERVICE = 'e3a87d11187d0b7e958a7f90c86dfca56bca8bb880e8be1f06499d312b21ece4'
SECURITY = '0534d97c0deba2f33744091b828da6a8a4e375d46c44ef2ca938f2088f148489'
ALLOW = {'.cs', '.csproj', '.json', '.txt', '.py', '.ps1', '.md', '.props', '.config', '.slnx', '.yml', '.log', '.stdout', '.stderr'}
SKIP = {'artifacts', 'bin', 'obj', '.git', '.local', 'evidence', 'private', '.private-fixtures', '.secrets', 'secrets', 'env', '__pycache__', 'cache', 'packages', 'packagecache', 'downloads', 'sdk', 'sdk-downloads'}
copied, mapping, checks, source_union = {}, [], [], {}
blob_cache = {}


def read(path):
    return json.loads(Path(path).read_bytes())


def digest(data):
    return hashlib.sha256(data).hexdigest()


def sha(path):
    return digest(Path(path).read_bytes())


def rel(value):
    p = PurePosixPath(str(value).replace('\\', '/'))
    assert not p.is_absolute() and '..' not in p.parts and ':' not in str(p), value
    return Path(*p.parts)


def explicit_path(value):
    path = Path(value)
    assert path.is_absolute() and path.resolve().is_relative_to(B.resolve()), value
    return path


def allowed(path):
    name = path.name.lower()
    return (path.suffix.lower() in ALLOW and not path.is_symlink()
            and not name.startswith(('private', '.env'))
            and name not in {'env', 'environment.json', 'environment.txt'})


def put(source, destination, expected=None):
    assert source.is_file() and allowed(source), str(source)
    data = source.read_bytes(); actual = digest(data)
    assert expected is None or actual == expected, str(source)
    destination = rel(destination); key = destination.as_posix(); target = OUT / destination
    assert len(str(target)) < 250, str(target)
    if key in copied:
        assert copied[key] == actual, str(target)
        return
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(data); copied[key] = actual


def copy_tree(root, destination):
    assert root.is_dir() and not root.is_symlink(), str(root)
    for current, dirs, files in os.walk(root, followlinks=False):
        dirs[:] = sorted(n for n in dirs if n.lower() not in SKIP and not n.lower().endswith('-artifacts')
                         and not n.lower().startswith(('private', '.private')) and not (Path(current) / n).is_symlink())
        for name in sorted(files):
            source = Path(current) / name
            if allowed(source): put(source, Path(destination) / source.relative_to(root))
    mapping.append({'local': str(root), 'archived': str(destination)})


def dump(name, data):
    target = OUT / rel(name)
    assert not target.exists(), str(target)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes((json.dumps(data, indent=2, ensure_ascii=True) + '\n').encode())


def blob(root, revision, path):
    assert re.fullmatch('[0-9a-f]{40}', revision), revision
    key = (str(root), revision, rel(path).as_posix())
    if key not in blob_cache:
        blob_cache[key] = subprocess.check_output(['git', '-C', str(root), 'show', revision + ':' + key[2]])
    return blob_cache[key]


def resolve_source(key, expected, engine, consumer):
    p = rel(key); prefix = p.parts[0]; tail = Path(*p.parts[1:])
    if prefix == 'engine': candidates = [(engine / tail, engine), (engine / 'src' / tail, engine)]
    elif prefix == 'consumer': candidates = [(consumer / tail, consumer), (consumer / 'security-api' / tail, consumer)]
    else: raise AssertionError(key)
    found = [(path, base) for path, base in candidates if path.is_file() and sha(path) == expected]
    assert found, (key, str(engine), str(consumer))
    path, base = found[0]
    return prefix, path.relative_to(base), path


def verify_and_retain_sources(source_map, engine, consumer, consumer_revision, archive=True):
    normalized = {}
    for key, expected in source_map.items():
        prefix, tail, path = resolve_source(key, expected, engine, consumer)
        canonical = prefix + '/' + tail.as_posix()
        git_root, revision = (E, ENGINE) if prefix == 'engine' else (S, consumer_revision)
        assert digest(blob(git_root, revision, tail)) == expected, ('committed-source', canonical, revision)
        assert canonical not in normalized or normalized[canonical] == expected
        normalized[canonical] = expected
        if archive:
            destination = ('final-engine-source' if prefix == 'engine' else 'final-consumer-source')
            put(path, Path(destination) / tail, expected)
            assert canonical not in source_union or source_union[canonical] == expected
            source_union[canonical] = expected
    return normalized


def observed_status(root):
    manifest = root / 'manifest.json'
    return read(manifest).get('status', 'manifest-without-status') if manifest.is_file() else 'retained-files-without-manifest'


def find_frozen(root, key):
    choices = [root / 'frozen-source' / rel(key), root / rel(key)]
    found = [path for path in choices if path.is_file()]
    assert found, ('missing-frozen-source', str(root), key)
    return found[0]


def verify_freeze(entry, consumer_revision, declarations):
    root = explicit_path(entry['path']); m = read(root / 'manifest.json')
    source_map = m['source_sha256']; actual = {}
    matches_final = entry.get('matches_final', False)
    revision = consumer_revision if matches_final else entry.get('consumer_revision')
    for key, expected in source_map.items():
        frozen = find_frozen(root, key); assert sha(frozen) == expected, (str(root), key)
        prefix, tail = key.split('/', 1); assert prefix in {'engine', 'consumer'}
        canonical = prefix + '/' + rel(tail).as_posix(); actual[canonical] = expected
        if matches_final:
            base = E if prefix == 'engine' else S
            assert sha(base / rel(tail)) == expected, ('current-freeze', key)
        if prefix == 'engine' or revision:
            assert digest(blob(E if prefix == 'engine' else S, ENGINE if prefix == 'engine' else revision, tail)) == expected, ('frozen-commit', key)
    declared = m.get('declaration_sha256', {})
    for key, expected in declared.items():
        frozen_options = [root / 'declaration' / rel(key), root / 'frozen-declarations' / rel(key)]
        frozen = next((p for p in frozen_options if p.is_file()), None)
        assert frozen is not None and sha(frozen) == expected, ('frozen-declaration', key)
        candidates = [decl_root / rel(key) for decl_root in declarations]
        # A retained corrected freezer may version declaration keys as 01/path.
        parts = rel(key).parts
        if len(parts) > 1 and re.fullmatch(r'\d+', parts[0]):
            candidates += [decl_root / Path(*parts[1:]) for decl_root in declarations if decl_root.name.endswith(parts[0])]
        assert any(p.is_file() and sha(p) == expected for p in candidates), ('declared-current-copy', key)
    checks.append({'source_freeze': entry['archive'], 'observed_status': m.get('status'),
                   'frozen_source_files_verified': len(actual), 'declaration_files_verified': len(declared),
                   'matches_final_current_and_committed': matches_final,
                   'consumer_commit_verified': revision,
                   'historical_uncommitted_consumer_limit': not matches_final and revision is None})
    return actual


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--consumer-revision', required=True)
    parser.add_argument('--config', type=Path)
    args = parser.parse_args()
    assert re.fullmatch('[0-9a-f]{40}', args.consumer_revision)
    cfg = read(args.config) if args.config else {}
    host_revision = cfg.get('host_revision', HOST_REVISION)
    defaults = [
        {'path': str(E / '.local/ara-final-driver01'), 'archive': 'attempts/a01', 'kind': 'final-driver'},
        {'path': str(S / '.local/audit-read-admission-windows-dev01'), 'archive': 'attempts/a02', 'kind': 'development'},
        {'path': str(S / '.local/audit-read-admission-windows-dev01-source'), 'archive': 'attempts/a03', 'kind': 'source-freeze'},
    ]
    attempts = defaults + cfg.get('extra_attempts', [])
    latest = cfg.get('latest_source_freeze', defaults[2]['path'])
    assert any(x['path'] == latest and x.get('kind') == 'source-freeze' for x in attempts), 'latest freeze must also be retained as an attempt'
    attempts = [dict(x, matches_final=x['path'] == latest) if x.get('kind') == 'source-freeze' else x for x in attempts]
    declarations = [{'path': str(D / '.local/audit-read-admission-declaration01'), 'archive': 'declaration/d01'}] + cfg.get('extra_declarations', [])
    driver_script = explicit_path(cfg.get('driver_script', str(E / '.local/run-audit-read-admission-final.py')))
    review = explicit_path(cfg.get('review', str(D / '.local/audit-read-admission-independent-review.json')))
    cleanup = explicit_path(cfg.get('cleanup', str(S / '.local/audit-read-admission-fixture-cleanup.json')))
    baseline = explicit_path(cfg.get('hosted_ci_baseline', str(D / 'internal/evidence/audit-read-admission/hosted-ci-baseline.json')))
    finals = [
        (S / '.local/ara-security-windows-final01', 'https/win', 85, 651, E, S),
        (SW / '.local/ara-security-wsl-final01', 'https/wsl', 85, 651, EW, SW),
        (S / '.local/audit-read-admission-windows-dev01', 'postgres/win', 110, 332, E, S),
        (SW / '.local/ara-postgres-wsl-final01', 'postgres/wsl', 110, 332, EW, SW),
    ]
    preparation_names = ['pg-reactivation-setup01.json', 'pg-reactivation-setup01-interrupted.json',
                         'pg-reactivation-setup02-failure.json', 'pg-reactivation-recovery02.py.txt',
                         'pg-reactivation-setup03.json']
    required = [driver_script, review, cleanup, baseline, HOST / '.local/audit-read-admission-worktree-preparation.json', HOST / '.local/audit-read-admission-host-source/source-check.json']
    required += [S / '.local' / name for name in preparation_names]
    assert all(path.is_file() for path in required), [str(p) for p in required if not p.is_file()]
    assert all(explicit_path(x['path']).is_dir() for x in attempts + declarations)
    assert len({x['archive'] for x in attempts + declarations}) == len(attempts + declarations), 'duplicate archive destination'
    final_manifests = [read(root / 'manifest.json') for root, *_ in finals]
    for (root, destination, expected_inputs, expected_total, *_), m in zip(finals, final_manifests):
        assert m['status'] == 'passed' and len(m['source_sha256']) == expected_inputs, destination
        assert m.get('total_passed', m.get('passed')) == expected_total, destination
        assert m['engine_revision'] == ENGINE and m['consumer_revision'] == args.consumer_revision
        assert not m.get('engine_dirty') and not m.get('consumer_source_dirty')
    driver = read(E / '.local/ara-final-driver01/manifest.json'); assert driver['status'] == 'passed'
    assert read(review)['status'] == 'passed_all_declared_review_scopes'
    assert read(cleanup)['status'] == 'passed'
    ci = read(baseline)
    assert ci['engine_revision'] == ENGINE and ci['baseline_only'] is True
    execution_flags = {k: v for k, v in ci.items() if k.startswith('new_') and k.endswith('_execution')}
    assert execution_flags and all(value is False for value in execution_flags.values())
    assert ci['component_baseline'] == {'windows': 1523, 'wsl': 1520}
    jobs = [job for run in ci['runs'] for job in run['jobs']]
    assert len(jobs) == 4 and all(job['conclusion'] == 'success' for job in jobs)
    OUT.mkdir(parents=True, exist_ok=False)
    for root, destination, *_ in finals: copy_tree(root, destination)
    for entry in attempts:
        root = explicit_path(entry['path']); copy_tree(root, entry['archive'])
        checks.append({'retained_attempt': entry['archive'], 'kind': entry.get('kind'), 'observed_status': observed_status(root)})
    declaration_roots = []
    for entry in declarations:
        root = explicit_path(entry['path']); declaration_roots.append(root); copy_tree(root, entry['archive'])
        m = read(root / 'manifest.json'); docs = m.get('files', m.get('source_sha256'))
        expected_docs = 1 if m.get('status') == 'frozen_while_first_dev_pending_before_result' else 3
        assert docs and len(docs) == expected_docs
        for key, expected in docs.items(): assert sha(root / rel(key)) == expected, key
        checks.append({'declaration': entry['archive'], 'documents_verified': len(docs), 'observed_status': m.get('status')})
    pair_sources = []
    for offset, name in ((0, 'https'), (2, 'postgres')):
        a, b = final_manifests[offset:offset + 2]
        assert a['source_sha256'] == b['source_sha256'], name
        for field in ('registry_sha256', 'registry_digests', 'relay_registry_sha256', 'service_registry_sha256', 'security_registry_sha256'):
            if field in a: assert a[field] == b[field], (name, field)
        if name == 'https':
            assert a['registry_sha256'] == SECURITY
            for index in (offset, offset + 1): assert sha(finals[index][0] / 'generated.g.cs.txt') == SECURITY
        else:
            assert a['relay_registry_sha256'] == a['service_registry_sha256'] == SERVICE and a['security_registry_sha256'] == SECURITY
            for index in (offset, offset + 1): assert sha(finals[index][0] / 'generated-relay.g.cs.txt') == SERVICE
        normalized = []
        for index in (offset, offset + 1):
            root, _, _, _, engine, consumer = finals[index]
            m = final_manifests[index]
            normalized.append(verify_and_retain_sources(m['source_sha256'], engine, consumer, args.consumer_revision))
            frozen = root / 'frozen-source'
            if frozen.is_dir():
                for key, expected in m['source_sha256'].items(): assert sha(find_frozen(root, key)) == expected, (name, key)
        assert normalized[0] == normalized[1], name
        pair_sources.append(normalized[0])
        checks.append({'pair': name, 'source_count': len(a['source_sha256']), 'current_both_hosts_explicit_commit_blobs_and_registry_bytes_match': True})
    latest_map = None
    for entry in attempts:
        if entry.get('kind') == 'source-freeze':
            frozen = verify_freeze(entry, args.consumer_revision, declaration_roots)
            if entry['matches_final']: latest_map = frozen
    assert latest_map is not None
    if 'expected_freeze_inputs' in cfg: assert len(latest_map) == cfg['expected_freeze_inputs']
    separately_frozen = {}
    for pair in pair_sources:
        for key, value in pair.items():
            if latest_map.get(key) == value: continue
            # Historical freezer layouts omit this one verifier; actual per-lane
            # executing verifier copies remain required, not inferred from current bytes.
            assert key == 'consumer/tools/verify_optional_security.py'
            for index in (0, 1): assert sha(finals[index][0] / 'frozen-verifier.py.txt') == value
            separately_frozen[key] = value
    # The freezer includes inputs such as CodeGeneration/NuGet.Config beyond verifier maps.
    verify_and_retain_sources(latest_map, E, S, args.consumer_revision)
    if 'expected_source_union' in cfg: assert len(source_union) == cfg['expected_source_union'], len(source_union)
    checks.append({'actual_latest_pre_sdk_source_inputs': len(latest_map),
                   'normalized_final_and_pre_sdk_union_committed_inputs': len(source_union),
                   'separately_frozen_executing_security_verifiers': separately_frozen,
                   'sources_not_promoted_from_failed_historical_freezes': True})
    host_file = HOST / 'audit-outbox/AuditReceiptTransportHost.cs'
    source_proof = read(HOST / '.local/audit-read-admission-host-source/source-check.json')
    assert sha(host_file) == source_proof['after_sha256']
    host_matches_final = sha(host_file) == sha(S / 'audit-outbox/AuditReceiptTransportHost.cs')
    if not host_matches_final:
        correction = cfg.get('host_final_correction')
        assert isinstance(correction, dict) and correction.get('reason'), 'Final host differs: retain and declare the correction explicitly'
        assert correction.get('declaration_archive') in {x['archive'] for x in declarations}
    assert host_file.read_bytes() == blob(S, host_revision, 'audit-outbox/AuditReceiptTransportHost.cs')
    assert source_proof['before_sha256'] == digest(blob(S, BASELINE, 'audit-outbox/AuditReceiptTransportHost.cs'))
    assert (HOST / '.local/audit-read-admission-host-source/before.cs').read_bytes() == blob(S, BASELINE, 'audit-outbox/AuditReceiptTransportHost.cs')
    assert (HOST / '.local/audit-read-admission-host-source/after.cs').read_bytes() == host_file.read_bytes()
    assert b'[Operation(' not in host_file.read_bytes()
    copy_tree(HOST / '.local/audit-read-admission-host-source', 'host-source-review')
    put(HOST / '.local/audit-read-admission-worktree-preparation.json', 'host-source-review/worktree-preparation.json')
    put(HOST / '.local/record-host-source.py', 'host-source-review/record-host-source.py')
    checks.append({'host_source_commit': host_revision, 'baseline_host_before_and_committed_after_exact': True,
                   'host_commit_source_matches_final': host_matches_final,
                   'declared_final_host_correction': cfg.get('host_final_correction'),
                   'preparation_failure_retained': True, 'source_only_host_work_no_sdk_claim': True})
    # Runtime names/passed flags are stable proof; schema names/backend IDs are invocation-specific.
    old_provider = read(B / '.worktrees/arh-consumer/.local/arh-postgres-windows-final01/tests.json')
    old_security = read(B / '.worktrees/arh-consumer/.local/arh-security-windows-final01/tests.json')
    for index, (root, _, _, total, *_) in enumerate(finals):
        tests = read(root / 'tests.json'); old = old_security if index < 2 else old_provider
        old_cases = [(x['name'], x['passed']) for x in old['checks']]
        current = [(x['name'], x['passed']) for x in tests['checks']]
        assert current[:len(old_cases)] == old_cases
        assert tests['failed'] == 0 and all(passed is True for _, passed in current)
        if index >= 2:
            assert len(current) == 329 and len(old_cases) == 305
            for key, values in old.items():
                if key.endswith('_observations'):
                    assert key in tests and len(tests[key]) == len(values), key
                    assert [x.get('phase') for x in tests[key]] == [x.get('phase') for x in values], key
            new_observations = [v for key, v in tests.items() if key.endswith('_observations') and key not in old]
            assert len(new_observations) == 1 and len(new_observations[0]) == 24
        checks.append({'actual_cases': finals[index][1], 'old_passed_case_prefix': len(old_cases), 'failed': tests['failed'], 'declared_total_including_restart': total, 'original_observation_arrays_retained': index >= 2})
    runner_digest = driver['runner_sha256']
    put(driver_script, 'final-driver.py', runner_digest)
    assert sha(E / '.local/ara-final-driver01/runner.py.txt') == runner_digest
    dump('final-driver-proof.json', {'sha256': runner_digest, 'executing_copy_matches_direct_runner': True, 'changed_consumer_lanes': 4, 'new_engine_component_or_hosted_ci_runs': 0})
    put(baseline, 'hosted-ci-baseline.json'); put(review, 'independent-review.json'); put(cleanup, 'cleanup-and-preparation/fixture-cleanup.json')
    for name in preparation_names: put(S / '.local' / name, Path('cleanup-and-preparation') / name)
    for root, names in [(S, ['.local/postgres18-fixture.json',
                            '.local/pg-proxy-native-listener-before.json', '.local/pg-proxy-native-listener-cleanup-before.json', '.local/pg-proxy-native-listener-after.json', '.local/cleanup-owned-ga-pg.py']),
                        (D, ['.local/freeze-audit-read-admission-source.py', '.local/setup-audit-read-admission-fixture.py'])]:
        for name in names:
            source = root / name
            if source.is_file(): put(source, Path('cleanup-and-preparation') / source.name)
    for suffix in ('.json', '.stdout', '.stderr'):
        source = E / ('.local/ara-final-launch' + suffix)
        if source.is_file(): put(source, Path('helpers') / source.name)
    for entry in cfg.get('extra_files', []):
        put(explicit_path(entry['path']), entry['archive'])
        mapping.append({'local': entry['path'], 'archived': entry['archive']})
    put(Path(__file__), 'exporter.py')
    if args.config: put(args.config.resolve(), 'export-config.json')
    checks.append({'engine_revision_unchanged': ENGINE, 'components_1523_1520_and_four_hosted_jobs_reused_baseline_only': True, 'no_new_hosted_or_component_execution_claim': True})
    dump('source-input-union.json', source_union)
    dump('attempt-path-map.json', mapping)
    dump('source-inventory-checks.json', checks)
    summary = {'copied_files': len(copied), 'final_files': sum(p.is_file() for p in OUT.rglob('*')) + 1,
               'new_functional_final_lanes': 4, 'new_engine_component_or_ci_execution': False,
               'normalized_committed_source_union': len(source_union), 'attempts_retained': len(attempts),
               'declarations_retained': len(declarations), 'source_checks': checks,
               'all_actual_attempts_must_be_supplied_by_root_config': True,
               'private_inputs_build_outputs_git_objects_sdk_excluded_by_explicit_selection': True,
               'privacy_review_sha256sums_and_index_check_pending_root': True}
    dump('export-summary.json', summary)
    print(json.dumps(summary))


if __name__ == '__main__':
    main()
