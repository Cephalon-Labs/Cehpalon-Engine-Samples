"""Owned local provider fixtures for SDK/driver qualification, not sample E2E.

Images must be locked by Linux platform manifest digest. Secrets and owned IDs
live under ignored .local; evidence contains no credentials, tokens or env dump.
"""
import argparse
import base64
import json
import secrets
import socket
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PRIVATE = ROOT / '.local/qualification'
STATE = PRIVATE / 'owned-state.json'
EVIDENCE = ROOT / 'qualification/evidence/provider-smoke.json'
OWNER = 'cehpalon.w0.qualification'


def save(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + '\n', encoding='utf-8', newline='\n')


def docker(*args, log=None):
    result = subprocess.run(['docker', *map(str, args)], capture_output=True, text=True, encoding='utf-8')
    if log:
        log.parent.mkdir(parents=True, exist_ok=True)
        log.write_text(result.stdout + result.stderr, encoding='utf-8', newline='\n')
    if result.returncode:
        raise RuntimeError(f'Docker operation failed ({args[0]}); see retained operation logs')
    return result.stdout.strip()


def request(url, payload=None, token=None, form=False, method=None):
    headers = {}
    if token:
        headers['Authorization'] = 'Bearer ' + token
    if payload is not None:
        headers['Content-Type'] = 'application/x-www-form-urlencoded' if form else 'application/json'
        data = urllib.parse.urlencode(payload).encode() if form else json.dumps(payload).encode()
    else:
        data = None
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    with urllib.request.urlopen(req, timeout=10) as response:
        body = response.read()
        return response.status, json.loads(body) if body else None


def wait_tcp(port, seconds=90):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(('127.0.0.1', port), timeout=1):
                return
        except OSError:
            time.sleep(.5)
    raise TimeoutError('Fixture listener readiness timeout')


def start(lock):
    if STATE.exists():
        previous = json.loads(STATE.read_text(encoding='utf-8'))
        if not previous.get('stopped'):
            raise RuntimeError('Owned state already exists; inspect or stop it before creating another fixture set')
        save(PRIVATE / 'history' / (previous['run_id'] + '.json'), previous)
    images = json.loads(lock.read_text(encoding='utf-8'))['images']
    required = ['postgresql', 'rabbitmq', 'keycloak', 'qdrant', 'valkey-optional']
    images = {row['name']: row for row in images if row.get('status') == 'verified-registry-metadata'}
    if any(name not in images or '@sha256:' not in images[name]['pull_reference'] for name in required):
        raise ValueError('All selected images need verified immutable platform references')
    PRIVATE.mkdir(parents=True, exist_ok=True)
    run_id = uuid.uuid4().hex[:12]
    label = OWNER + '=' + run_id
    network = 'cehpalon-w0-' + run_id
    state = {'run_id': run_id, 'label': label, 'network': network, 'nodes': {}}
    save(STATE, state)
    # Docker25 internal networks did not expose requested loopback host bindings.
    # Use an owned bridge with loopback-only published ports; no egress-isolation claim.
    docker('network', 'create', '--label', label, network)
    ports = {'postgresql': 5432, 'rabbitmq': 5672, 'keycloak': 8080, 'qdrant': 6333, 'valkey-optional': 6379}
    for name in required:
        image = images[name]
        docker('pull', '--platform', 'linux/amd64', image['pull_reference'], log=PRIVATE / 'logs' / (name + '-pull.txt'))
        image_id = docker('image', 'inspect', image['pull_reference'], '--format', '{{.Id}}')
        if image_id != image['config_digest']:
            raise ValueError(name + ': installed image config differs from verified registry config')
        password = secrets.token_hex(24)
        env = {}
        if name == 'postgresql':
            env = {'POSTGRES_DB': 'cehpalon_qual', 'POSTGRES_USER': 'cehpalon_qual', 'POSTGRES_PASSWORD': password}
        elif name == 'rabbitmq':
            env = {'RABBITMQ_DEFAULT_USER': 'cehpalon_qual', 'RABBITMQ_DEFAULT_PASS': password}
        elif name == 'keycloak':
            env = {'KC_BOOTSTRAP_ADMIN_USERNAME': 'cehpalon-admin', 'KC_BOOTSTRAP_ADMIN_PASSWORD': password, 'KC_HOSTNAME_STRICT': 'false', 'KC_HEALTH_ENABLED': 'true'}
        env_file = PRIVATE / (name + '.env')
        env_file.write_text(''.join(key + '=' + value + '\n' for key, value in env.items()), encoding='utf-8', newline='\n')
        args = ['run', '--detach', '--pull=never', '--platform', 'linux/amd64', '--name', network + '-' + name,
                '--label', label, '--network', network, '--cpus', '2', '--memory', '2g',
                '--security-opt', 'no-new-privileges:true', '--env-file', str(env_file),
                '-p', f'127.0.0.1::{ports[name]}', image['pull_reference']]
        if name == 'keycloak':
            args += ['start-dev', '--http-enabled=true']
        container = docker(*args)
        state['nodes'][name] = {'id': container, 'image': image['pull_reference'], 'config_digest': image_id,
                               'host': '127.0.0.1', 'port': None, 'user': 'cehpalon_qual', 'password': password}
        save(STATE, state)
        bindings = json.loads(docker('inspect', container, '--format', '{{json .NetworkSettings.Ports}}'))
        host_port = int(bindings[str(ports[name]) + '/tcp'][0]['HostPort'])
        state['nodes'][name]['port'] = host_port
        save(STATE, state)
        print(name + ': owned fixture started on loopback', flush=True)
    print('Fixture endpoints/secrets saved privately; no credentials printed.', flush=True)


def probe():
    state = json.loads(STATE.read_text(encoding='utf-8'))
    if EVIDENCE.exists():
        previous = EVIDENCE.read_bytes()
        archive = EVIDENCE.with_name('provider-smoke-prior-' + str(time.time_ns()) + '.json')
        archive.write_bytes(previous)
    report = {'observed_at_utc': datetime.now(timezone.utc).isoformat(), 'run_id': state['run_id'], 'scope': 'Local image/HTTP/protocol smoke only; no Engine/sample E2E, HA, TLS/production, network-egress isolation or benchmark proof', 'nodes': {}}
    save(EVIDENCE, report)
    for name, node in state['nodes'].items():
        actual = json.loads(docker('inspect', node['id'], '--format', '{{json .Config.Labels}}'))
        if actual.get(OWNER) != state['run_id']:
            raise ValueError('Fixture ownership changed')
        wait_tcp(node['port'])
        os_release = docker('exec', node['id'], 'cat', '/etc/os-release')
        entry = {'image': node['image'], 'installed_config_digest': node['config_digest'], 'os_release': os_release, 'listener_loopback': True}
        if name == 'postgresql':
            entry['version'] = docker('exec', node['id'], 'postgres', '--version')
            entry['server_version'] = docker('exec', node['id'], 'psql', '-U', node['user'], '-d', 'cehpalon_qual', '-Atc', 'SELECT version()')
        elif name == 'rabbitmq':
            entry['version'] = docker('exec', node['id'], 'rabbitmq-diagnostics', '-q', 'server_version')
            entry['erlang'] = docker('exec', node['id'], 'rabbitmq-diagnostics', '-q', 'erlang_version')
        elif name == 'keycloak':
            entry['version'] = docker('exec', node['id'], '/opt/keycloak/bin/kc.sh', '--version')
            entry['java'] = docker('exec', node['id'], 'java', '-version', log=PRIVATE / 'logs/keycloak-java.txt') or (PRIVATE / 'logs/keycloak-java.txt').read_text(encoding='utf-8')
            root = f"http://127.0.0.1:{node['port']}"
            deadline = time.monotonic() + 120
            while True:
                try:
                    _, token_data = request(root + '/realms/master/protocol/openid-connect/token', {'grant_type': 'password', 'client_id': 'admin-cli', 'username': 'cehpalon-admin', 'password': node['password']}, form=True)
                    break
                except (OSError, urllib.error.HTTPError):
                    if time.monotonic() > deadline:
                        raise TimeoutError('Keycloak bootstrap readiness timeout')
                    time.sleep(1)
            admin = token_data['access_token']
            realm = 'cehpalon-w0'
            client = 'cehpalon-qualification'
            request(root + '/admin/realms', {'realm': realm, 'enabled': True, 'sslRequired': 'none'}, admin)
            request(root + f'/admin/realms/{realm}/clients', {'clientId': client, 'enabled': True, 'publicClient': True, 'directAccessGrantsEnabled': True,
                    'protocolMappers': [{'name': 'audience', 'protocol': 'openid-connect', 'protocolMapper': 'oidc-audience-mapper', 'config': {'included.client.audience': client, 'access.token.claim': 'true', 'id.token.claim': 'false'}}]}, admin)
            request(root + f'/admin/realms/{realm}/users', {'username': 'cehpalon-user', 'firstName': 'Qualification', 'lastName': 'Fixture', 'email': 'qualification@example.invalid', 'enabled': True, 'emailVerified': True, 'credentials': [{'type': 'password', 'value': node['password'], 'temporary': False}]}, admin)
            authority = root + '/realms/' + realm
            _, discovery = request(authority + '/.well-known/openid-configuration')
            assert discovery['issuer'] == authority
            _, jwks = request(discovery['jwks_uri'])
            _, issued = request(discovery['token_endpoint'], {'grant_type': 'password', 'client_id': client, 'username': 'cehpalon-user', 'password': node['password']}, form=True)
            parts = issued['access_token'].split('.')
            decode = lambda text: base64.urlsafe_b64decode(text + '=' * (-len(text) % 4))
            header, claims = [json.loads(decode(text)) for text in parts[:2]]
            assert claims['iss'] == authority and client in ([claims['aud']] if isinstance(claims['aud'], str) else claims['aud'])
            assert header['alg'] == 'RS256'
            key = next(key for key in jwks['keys'] if key.get('kid') == header['kid'])
            from cryptography.hazmat.primitives.asymmetric import padding, rsa
            from cryptography.hazmat.primitives import hashes
            public_key = rsa.RSAPublicNumbers(int.from_bytes(decode(key['e']), 'big'), int.from_bytes(decode(key['n']), 'big')).public_key()
            public_key.verify(decode(parts[2]), (parts[0] + '.' + parts[1]).encode(), padding.PKCS1v15(), hashes.SHA256())
            node.update({'authority': authority, 'audience': client, 'access_token': issued['access_token']})
            save(STATE, state)
            entry.update({'discovery_issuer_exact': True, 'jwks_rsa_signature_verified': True, 'audience_verified': True, 'fixture_only_password_grant': True, 'transport': 'HTTP over owned loopback-only fixture; no TLS trust claim'})
        elif name == 'qdrant':
            root = f"http://127.0.0.1:{node['port']}"
            _, version = request(root + '/')
            entry['version'] = version
            request(root + '/collections/w0_qualification', {'vectors': {'size': 3, 'distance': 'Cosine'}}, method='PUT')
            request(root + '/collections/w0_qualification/points?wait=true', {'points': [{'id': 1, 'vector': [1., 0., 0.], 'payload': {'tenant': 'A'}}, {'id': 2, 'vector': [0., 1., 0.], 'payload': {'tenant': 'B'}}]}, method='PUT')
            _, found = request(root + '/collections/w0_qualification/points/query', {'query': [1., 0., 0.], 'limit': 5, 'with_payload': True, 'filter': {'must': [{'key': 'tenant', 'match': {'value': 'A'}}]}})
            assert [point['id'] for point in found['result']['points']] == [1]
            entry['filtered_vector_upsert_query'] = True
        elif name == 'valkey-optional':
            entry['version'] = docker('exec', node['id'], 'valkey-server', '--version')
            entry['ping'] = docker('exec', node['id'], 'valkey-cli', 'PING')
            assert entry['ping'] == 'PONG'
        report['nodes'][name] = entry
        save(EVIDENCE, report)
        print(name + ': bounded provider smoke passed', flush=True)
    report['success'] = True
    save(EVIDENCE, report)


def stop():
    state = json.loads(STATE.read_text(encoding='utf-8'))
    removed = []
    for name, node in state['nodes'].items():
        labels = json.loads(docker('inspect', node['id'], '--format', '{{json .Config.Labels}}'))
        if labels.get(OWNER) != state['run_id']:
            raise ValueError('Refusing to remove a container without the expected owned label')
        docker('rm', '-f', '-v', node['id'])
        removed.append(name)
    labels = json.loads(docker('network', 'inspect', state['network'], '--format', '{{json .Labels}}'))
    if labels.get(OWNER) != state['run_id']:
        raise ValueError('Refusing network removal without owned label')
    docker('network', 'rm', state['network'])
    closed_ports = {}
    for name, node in state['nodes'].items():
        try:
            with socket.create_connection(('127.0.0.1', node['port']), timeout=.5):
                closed_ports[name] = False
        except OSError:
            closed_ports[name] = True
        node.pop('password', None)
        node.pop('access_token', None)
        env_file = PRIVATE / (name + '.env')
        if env_file.resolve().parent != PRIVATE.resolve():
            raise ValueError('Credential cleanup path escaped owned private directory')
        if env_file.exists():
            env_file.unlink()
    cleanup = {'run_id': state['run_id'], 'removed': removed, 'network_removed': True,
               'owned_loopback_ports_closed': closed_ports, 'current_credentials_removed': True}
    save(PRIVATE / 'cleanup.json', cleanup)
    save(ROOT / 'qualification/evidence/cleanup.json', cleanup)
    state['stopped'] = True
    save(STATE, state)
    print('Removed only verified owned fixtures and their anonymous volumes/network.', flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=['start', 'probe', 'stop'])
    parser.add_argument('--lock', type=Path)
    args = parser.parse_args()
    if args.mode == 'start':
        if not args.lock:
            parser.error('--lock is required for start')
        start(args.lock)
    elif args.mode == 'probe':
        probe()
    else:
        stop()
