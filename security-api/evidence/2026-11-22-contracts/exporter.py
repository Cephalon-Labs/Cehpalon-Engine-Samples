"""Root-only targeted audit contract evidence export AFTER all SDK phases stop.

Prepare/AST validation needs no phase output directories. Execution requires
--execute-after-sdk-complete --consumer-revision SHA --config JSON.
No SDK, Git mutation, container, network, privacy scan or SHA/index publication.
Read-only git show verifies explicit committed blobs. Prior332/651 and Core/CI
remain REUSED baseline; targeted16 per host never become a fresh348 total.

Config requires receipts keys offline_fixture_stopped/design_review/host_review/
consumer_review/independent_review/fixture_cleanup/reused_baseline. Each receipt
entry has path, archive, assertions (a nonempty exact top-level field/value map).
Use actual receipt statuses, e.g passed_source_review_only or baseline_only=true.
Extra actual attempts/files/declarations are additive and must all be supplied
by root; never replace a failed attempt. Manifest/source layouts are the actual
tools/verify_audit_contracts.py interface. Artifact/binary/source counts derive
from retained outputs, not fixed totals. Private/binary/cache inputs stay local.
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
S = B / '.worktrees/ahx-consumer'
SW = B / '.worktrees/ahx-wsl-consumer'
HOST = B / '.worktrees/ahx-export'
OUT = B / 'Cehpalon-Engine-Samples/security-api/evidence/2026-11-22-contracts'
ENGINE = '5184517a92a087abe4e0091d256142b6c35a2b39'
BASELINE = 'e30fd5c97c792b0b78e8838fa3ae1cba69451bb7'
HOST_REVISION = 'e97e0db600de8d3daa710d6d4b3e04592dd9a4fb'
SERVICE = 'e3a87d11187d0b7e958a7f90c86dfca56bca8bb880e8be1f06499d312b21ece4'
SECURITY = '0534d97c0deba2f33744091b828da6a8a4e375d46c44ef2ca938f2088f148489'
ALLOW = {'.cs', '.csproj', '.json', '.txt', '.py', '.ps1', '.md', '.props', '.config', '.slnx', '.yml', '.log', '.stdout', '.stderr', '.graphql', '.yaml'}
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
    private_parts = {'private', 'secrets', '.secrets', 'env', '.private-fixtures'}
    return (path.suffix.lower() in ALLOW and not path.is_symlink()
            and not any(part.lower() in private_parts or part.lower().startswith(('private-', '.private')) for part in path.resolve().parts)
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
    revision = consumer_revision if matches_final else (entry.get('consumer_revision') or m.get('consumer_head') or m.get('consumer_revision'))
    if not matches_final: assert isinstance(revision, str) and re.fullmatch('[0-9a-f]{40}', revision), 'Historical committed freeze must identify its own consumer revision'
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


def windows_path(value):
    value = str(value).replace('\\', '/')
    if value.startswith('/mnt/d/'): value = 'D:/' + value[len('/mnt/d/'):]
    return explicit_path(value)


def check_phase(root, phase, engine, consumer, revision, declarations):
    m = read(root / 'manifest.json'); tests = read(root / 'tests.json')
    assert m['status'] == 'passed' and m['phase'] == phase and m['passed'] == 8 and m['failed'] == 0
    assert m['source_unchanged'] is True and m['engine_revision'] == ENGINE and m['consumer_revision'] == revision
    assert tests['phase'] == phase and tests['passed'] == 8 and tests['failed'] == 0
    assert len(tests['checks']) == len(tests['observations']) == 8
    assert all(x['passed'] is True for x in tests['checks'])
    current = verify_and_retain_sources(m['source_sha256'], engine, consumer, revision)
    for key, expected in m['source_sha256'].items(): assert sha(find_frozen(root, key)) == expected, (root, key)
    legacy = m['legacy_source_preservation']
    assert legacy['baseline'] == BASELINE and legacy['normal_program_tail_byte_identical'] is True
    assert legacy['prior_provider_332_and_security_651_reused_not_rerun'] is True
    for name, expected in legacy['preserved_source_sha256'].items():
        assert digest(blob(S, BASELINE, name)) == expected and sha(consumer / rel(name)) == expected, name
    marker = b'var arguments=args.Select'
    original = blob(S, BASELINE, 'audit-outbox/Program.cs'); present = (consumer / 'audit-outbox/Program.cs').read_bytes()
    assert present[present.index(marker):] == original[original.index(marker):]
    for filename, key, expected in [('generated-service.cs.txt', 'service_registry_sha256', SERVICE), ('generated-security.cs.txt', 'security_registry_sha256', SECURITY)]:
        assert m[key] == sha(root / filename) == expected, (root, filename)
    assert m['binary_sha256'], root
    if phase == 'offline':
        assert m['build_executed'] is True
        declaration = m['declaration_sha256']; assert declaration
        for key, expected in declaration.items():
            assert sha(root / 'frozen-declarations' / rel(key)) == expected, key
            parts = rel(key).parts
            candidates = [d / Path(*parts[1:]) for d in declarations if d.name == parts[0]]
            assert any(x.is_file() and sha(x) == expected for x in candidates), key
        assert sha(root / 'verifier.py.txt') == sha(consumer / 'tools/verify_audit_contracts.py')
        stdout = (root / 'build.stdout.txt').read_text(encoding='utf-8')
        assert '0 Warning(s)' in stdout and '0 Error(s)' in stdout, root
        assert m['sdk'] == '11.0.100'
        for key, expected in m['binary_sha256'].items(): assert sha(root / rel(key)) == expected, key
        artifacts = m['deterministic_artifact_sha256']; assert set(artifacts) == {'manifest.json', 'openapi.json', 'schema.graphql'}
        for name, expected in artifacts.items(): assert sha(root / 'contract-proof/deterministic' / name) == expected, name
    else:
        assert m['build_executed'] is False and m['exact_offline_binaries_reused'] is True
    checks.append({'phase': phase, 'local': str(root), 'new_checks': 8, 'source_inputs': len(current),
                   'current_frozen_explicit_commit_verified': True, 'unchanged_registry_bytes': True,
                   'legacy_source_preserved_not_legacy_suite_reexecution': True})
    return m, current


def receipt_entry(role, entry):
    source = explicit_path(entry['path']); value = read(source)
    assertions = entry.get('assertions'); assert isinstance(assertions, dict) and assertions, role
    for key, expected in assertions.items(): assert value.get(key) == expected, (role, key)
    if role != 'reused_baseline':
        status = value.get('status'); assert isinstance(status, str)
        assert status.startswith('passed') or role == 'design_review' and status in {'accepted', 'accepted_design'}, (role, status)
    put(source, entry.get('archive', 'receipts/' + role + '.json'))
    checks.append({'receipt': role, 'sha256': sha(source), 'assertions_verified': assertions})
    return value


def main():
    p = argparse.ArgumentParser(); p.add_argument('--consumer-revision', required=True); p.add_argument('--config', type=Path, required=True)
    p.add_argument('--execute-after-sdk-complete', action='store_true'); args = p.parse_args()
    assert args.execute_after_sdk_complete, 'Root must confirm all SDK phases are complete before evidence export'
    assert re.fullmatch('[0-9a-f]{40}', args.consumer_revision)
    cfg = read(args.config)
    required_receipts = {'offline_fixture_stopped', 'design_review', 'host_review', 'consumer_review', 'independent_review', 'fixture_cleanup', 'reused_baseline'}
    receipts = cfg.get('receipts', {}); assert required_receipts <= set(receipts), required_receipts - set(receipts)
    final_specs = [
        ('windows', 'offline', S / '.local/ahx-offline-windows01', 'offline/win', E, S),
        ('wsl', 'offline', SW / '.local/ahx-offline-wsl01', 'offline/wsl', EW, SW),
        ('windows', 'wire', S / '.local/ahx-wire-windows01', 'wire/win', E, S),
        ('wsl', 'wire', SW / '.local/ahx-wire-wsl01', 'wire/wsl', EW, SW)]
    displaced_phases = []
    for entry in cfg.get('phase_overrides', []):
        match = [(i, x) for i, x in enumerate(final_specs) if x[0] == entry['host'] and x[1] == entry['phase']]
        assert len(match) == 1
        i, old = match[0]
        if old[2].is_dir() and old[2] != explicit_path(entry['path']):
            displaced_phases.append({'path': str(old[2]), 'archive': 'attempts/original-' + old[0] + '-' + old[1], 'kind': 'original-phase-before-correction'})
        final_specs[i] = (old[0], old[1], explicit_path(entry['path']), old[3], old[4], old[5])
    assert len({str(x[2]) for x in final_specs}) == 4
    driver = explicit_path(cfg.get('driver_output', str(E / '.local/ahx-driver01')))
    driver_script = explicit_path(cfg.get('driver_script', str(E / '.local/run-audit-contract-export.py')))
    driver_frozen = explicit_path(cfg.get('driver_frozen_source', str(driver / 'runner.py.txt')))
    driver_manifest = read(driver / 'manifest.json'); assert driver_manifest['status'] == 'passed'
    assert driver_manifest['consumer_revision'] == args.consumer_revision and driver_manifest['engine_revision'] == ENGINE
    assert driver_manifest['phases'] and all(x.get('exit', x.get('exit_code')) == 0 for x in driver_manifest['phases'])
    assert driver_manifest['runner_sha256'] == sha(driver_script) == sha(driver_frozen)
    declarations = [{'path': str(D / '.local/audit-contract-export-declaration01'), 'archive': 'declaration/d01'}] + cfg.get('extra_declarations', [])
    declaration_roots = [explicit_path(x['path']) for x in declarations]
    attempts = [{'path': str(S / '.local/audit-contract-export-source01'), 'archive': 'attempts/source01', 'kind': 'source-freeze'}] + displaced_phases + cfg.get('extra_attempts', [])
    latest = cfg.get('latest_source_freeze', attempts[0]['path'])
    assert any(x['path'] == latest and x.get('kind') == 'source-freeze' for x in attempts)
    attempts = [dict(x, matches_final=x['path'] == latest) if x.get('kind') == 'source-freeze' else x for x in attempts]
    known_failures = [D / '.local/audit-contract-export-offline-fixture-attempt01.json', D / '.local/audit-contract-export-offline-fixture-attempt01.py.txt']
    assert all(x.is_file() for x in known_failures), 'Retain actual initial read-only WSL brace/controller preflight error and source'
    assert all((x[2] / 'manifest.json').is_file() for x in final_specs)
    assert all(explicit_path(x['path']).is_dir() for x in attempts + declarations)
    assert len({x['archive'] for x in attempts + declarations}) == len(attempts + declarations)
    OUT.mkdir(parents=True, exist_ok=False)
    for role in sorted(receipts): receipt_entry(role, receipts[role])
    ci = read(explicit_path(receipts['reused_baseline']['path']))
    assert ci['baseline_only'] is True and ci['engine_revision'] == ENGINE
    assert ci['component_baseline'] == {'windows': 1523, 'wsl': 1520}
    flags = {k: v for k, v in ci.items() if k.startswith('new_') and k.endswith('_execution')}; assert flags and not any(flags.values())
    jobs = [j for r in ci['runs'] for j in r['jobs']]; assert len(jobs) == 4 and all(j['conclusion'] == 'success' for j in jobs)
    prior_path = explicit_path(cfg.get('prior_consumer_baseline', str(D / 'internal/evidence/audit-read-admission/delivery.json')))
    prior = read(prior_path); assert prior['final_counts'] == [651, 651, 332, 332] and prior['engine_main'] == ENGINE
    put(prior_path, 'baseline/prior-consumer-delivery.json')
    checks.append({'baseline_only': True, 'prior_provider_per_host': 332, 'prior_security_per_host': 651,
                   'core_components': [1523, 1520], 'hosted_success_jobs': 4, 'old_sdk_raw_outputs_copied': False,
                   'new_provider_348_total_claimed': False, 'new_full_or_hosted_suite_execution_claimed': False})
    for entry in declarations:
        root = explicit_path(entry['path']); m = read(root / 'manifest.json'); source = m.get('files', m.get('source_sha256')); assert source
        for key, expected in source.items(): assert sha(root / rel(key)) == expected, key
        copy_tree(root, entry['archive']); checks.append({'declaration': entry['archive'], 'documents': len(source), 'actual_status': m.get('status')})
    phases, maps = {}, {}
    for host, phase, root, destination, engine, consumer in final_specs:
        m, current = check_phase(root, phase, engine, consumer, args.consumer_revision, declaration_roots)
        phases[host, phase] = (root, m); maps[host, phase] = current; copy_tree(root, destination)
    assert len({json.dumps(x, sort_keys=True) for x in maps.values()}) == 1, 'All four phases must retain identical canonical source maps'
    for host in ('windows', 'wsl'):
        offline, a = phases[host, 'offline']; wire, b = phases[host, 'wire']
        assert windows_path(b['offline_output']) == offline.resolve()
        assert b['offline_manifest_sha256'] == sha(offline / 'manifest.json') and a['binary_sha256'] == b['binary_sha256']
        for name, expected in b['binary_sha256'].items(): assert sha(offline / rel(name)) == expected, (host, name)
        checks.append({'host': host, 'builds': 1, 'offline_checks': 8, 'wire_checks': 8,
                       'same_binary_files_before_and_after_wire': len(b['binary_sha256']), 'binary_payloads_exported': False})
    aroot, am = phases['windows', 'offline']; broot, bm = phases['wsl', 'offline']
    assert am['deterministic_artifact_sha256'] == bm['deterministic_artifact_sha256']
    for name, expected in am['deterministic_artifact_sha256'].items():
        assert (aroot / 'contract-proof/deterministic' / name).read_bytes() == (broot / 'contract-proof/deterministic' / name).read_bytes()
    for dirname in ('wire-http', 'wire-graphql'):
        left = phases['windows', 'wire'][0] / 'contract-proof' / dirname; right = phases['wsl', 'wire'][0] / 'contract-proof' / dirname
        left_map = {x.name: sha(x) for x in left.iterdir() if x.is_file()}; right_map = {x.name: sha(x) for x in right.iterdir() if x.is_file()}
        assert set(left_map) == {'manifest.json', 'openapi.json', 'schema.graphql'} and left_map == right_map
    latest_map = None
    for entry in attempts:
        root = explicit_path(entry['path']); copy_tree(root, entry['archive'])
        if entry.get('kind') == 'source-freeze':
            m = read(root / 'manifest.json'); entry.setdefault('consumer_revision', m.get('consumer_head'))
            source = verify_freeze(entry, args.consumer_revision, declaration_roots)
            if entry['matches_final']: latest_map = source
        else: checks.append({'retained_actual_attempt': entry['archive'], 'status': observed_status(root)})
    assert latest_map is not None
    verify_and_retain_sources(latest_map, E, S, args.consumer_revision)
    phase_map = maps['windows', 'offline']; missing = {k: v for k, v in phase_map.items() if latest_map.get(k) != v}
    for key, expected in missing.items():
        for host in ('windows', 'wsl'): assert sha(find_frozen(phases[host, 'offline'][0], key)) == expected
    checks.append({'actual_source_freeze_inputs': len(latest_map), 'canonical_phase_inputs': len(phase_map),
                   'separately_frozen_pre_sdk_phase_inputs': missing, 'committed_source_union': len(source_union),
                   'source_counts_derived_not_hardcoded': True})
    copy_tree(driver, 'driver'); put(driver_script, 'driver/executing-runner.py', driver_manifest['runner_sha256'])
    host_proof = HOST / '.local/ahx-host-source'; proof = read(host_proof / 'source-check.json')
    assert proof['status'] == 'passed_source_checks_only' and proof['baseline'] == BASELINE
    for name, expected in proof['source_sha256'].items(): assert digest(blob(S, HOST_REVISION, name)) == expected
    host_differences = [name for name, expected in proof['source_sha256'].items() if sha(S / rel(name)) != expected]
    if host_differences:
        correction = cfg.get('host_final_correction')
        assert isinstance(correction, dict) and correction.get('reason'), 'Final host/export source correction must be explicitly declared and retained'
        assert correction.get('declaration_archive') in {x['archive'] for x in declarations}
    assert (host_proof / 'before-host.cs').read_bytes() == blob(S, BASELINE, 'audit-outbox/AuditReceiptTransportHost.cs')
    assert (host_proof / 'after-host.cs').read_bytes() == blob(S, HOST_REVISION, 'audit-outbox/AuditReceiptTransportHost.cs')
    copy_tree(host_proof, 'host-source-review'); put(HOST / '.local/ahx-host-preparation.json', 'host-source-review/preparation.json')
    put(HOST / '.local/record-ahx-host-source.py', 'host-source-review/record-source.py')
    checks.append({'host_source_revision': HOST_REVISION, 'original_host_source_git_blobs_verified': True,
                   'host_source_matches_final': not host_differences, 'host_source_final_differences': host_differences,
                   'declared_host_final_correction': cfg.get('host_final_correction')})
    cleanup_path = explicit_path(receipts['fixture_cleanup']['path']); fixture_root = cleanup_path.parent
    before = read(fixture_root / 'pg-proxy-native-listener-before.json'); after = read(fixture_root / 'pg-proxy-native-listener-after.json')
    assert before['listener_count'] == 1 and after['listener_count'] == 0 and before['port'] == after['port']
    cleanup = read(cleanup_path)
    assert cleanup['container_stopped'] and cleanup['owned_proxy_exited'] and int(cleanup['windows_proxy_bind'].rsplit(':', 1)[1]) == before['port']
    for name in ('postgres18-fixture.json', 'pg-proxy-native-listener-before.json', 'pg-proxy-native-listener-after.json',
                 'cleanup-owned-ga-pg.py', 'start-owned-helpers.ps1', 'pg-loopback-proxy.py', 'pg-wsl-anchor.py', 'pg-stdio-bridge.py'):
        put(fixture_root / name, 'preparation-and-cleanup/final/' + name)
    checks.append({'owned_listener_before_after': [1, 0], 'same_owned_port_and_cleanup_verified': True, 'configured_fixture_root': str(fixture_root),
                   'container_proxy_cleanup_passed': True, 'private_connection_files_exported': False})
    for source in known_failures: put(source, 'preparation/' + source.name)
    for entry in cfg.get('extra_files', []): put(explicit_path(entry['path']), entry['archive'])
    put(Path(__file__), 'exporter.py'); put(args.config.resolve(), 'export-config.json')
    dump('source-input-union.json', source_union); dump('attempt-path-map.json', mapping); dump('source-and-proof-checks.json', checks)
    summary = {'status': 'exported_pending_root_privacy_and_index_checks', 'targeted_checks_per_host': 16, 'targeted_checks_per_phase': 8,
               'new_sdk_builds_per_host': 1, 'wire_builds': 0, 'old332_651_core_ci_reused_only': True,
               'no_348_total_or_new_full_suite_claim': True, 'source_inputs': len(source_union),
               'copied_files': len(copied), 'final_files': sum(x.is_file() for x in OUT.rglob('*')) + 1,
               'declarations_retained': len(declarations), 'additive_actual_attempts_retained': len(attempts),
               'all_actual_attempts_must_be_supplied_by_root_config': True,
               'binary_private_build_cache_objects_and_inherited_evidence_excluded': True}
    dump('export-summary.json', summary); print(json.dumps(summary))


if __name__ == '__main__': main()
