"""Run already-built qualification against explicitly supplied owned local fixtures.

Reads credentials from the private state file; never echoes or writes them into
evidence. This does not create providers or change network bindings/trust stores.
"""
import argparse
import ipaddress
import json
import os
import subprocess
from pathlib import Path
from urllib.parse import quote

parser = argparse.ArgumentParser()
parser.add_argument('--dotnet', required=True)
parser.add_argument('--assembly', required=True)
parser.add_argument('--fixture-state', required=True)
parser.add_argument('--output', required=True)
args = parser.parse_args()
state = json.loads(Path(args.fixture_state).read_text(encoding='utf-8-sig'))
environment = dict(os.environ)


def local_node(name):
    node = state['nodes'][name]
    if not ipaddress.ip_address(node['host']).is_loopback:
        raise SystemExit('Only the explicitly owned loopback fixture is allowed')
    if not 1 <= int(node['port']) <= 65535:
        raise SystemExit('Invalid fixture port')
    return node


def pg_value(value):
    return '"' + str(value).replace('"', '""') + '"'


pg = local_node('postgresql')
environment['QUALIFICATION_POSTGRES'] = ';'.join([
    'Host=' + pg_value(pg['host']), 'Port=' + str(pg['port']), 'Database=cehpalon_qual',
    'Username=' + pg_value(pg['user']), 'Password=' + pg_value(pg['password']),
    'SSL Mode=Disable', 'Timeout=5'])
rabbit = local_node('rabbitmq')
environment['QUALIFICATION_RABBIT_URI'] = ('amqp://' + quote(rabbit['user'], safe='') + ':'
    + quote(rabbit['password'], safe='') + '@' + rabbit['host'] + ':' + str(rabbit['port']) + '/')
environment.update(DOTNET_CLI_TELEMETRY_OPTOUT='1', DOTNET_NOLOGO='1')
result = subprocess.run([args.dotnet, args.assembly, '--output=' + args.output], env=environment)
raise SystemExit(result.returncode)
