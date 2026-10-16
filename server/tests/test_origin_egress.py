# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Split ingress/egress policy reaches the existing agent without broad access."""
import copy
import ipaddress
import json
from pathlib import Path
import subprocess
import sys

import pytest

import auth
import instruction_stamper as stamper
import instructions
import peer_policy
from test_instruction_stamper import NOW, _setup, _policy_result, _write_policy, _raw_stamp

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / 'tools'))
from iris_installer import cli, deploy, kube_deploy, local_setup, split_deploy
from iris_installer.state import InstallError
from test_installer_install import config as docker_config
from test_installer_kube_deploy import config as kube_config
from test_installer_split_deploy import config as split_config, fake_files


def policy(origin=True, static=True):
    doc = peer_policy.base_document()
    definition = {'restricted': True, 'origin': origin}
    definition.update({'nets': ['198.51.100.104/32']} if static else {'peers': ['edge']})
    doc['roles'] = {'defs': {'edge': definition},
                    'role_of': {'device-1': 'edge', 'peer-2': 'edge'},
                    'qos_default': {}, 'qos_device': {}}
    return doc, definition


@pytest.mark.parametrize('static', [False, True])
@pytest.mark.parametrize('origin', [False, True])
def test_exact_origin_source_is_allowed_only_when_role_permits_it(tmp_path, monkeypatch, static, origin):
    monkeypatch.setenv('IRIS_ORIGIN_EGRESS_IPS', '192.0.2.86')
    paths, *_ = _setup(tmp_path)
    doc, definition = policy(origin, static)
    monkeypatch.setattr(stamper, '_endpoint_attribution', lambda *_: (
        {'198.51.100.105': {auth.Principal('device', 'device-1')},
         '198.51.100.104': {auth.Principal('device', 'peer-2')}},
        {'198.51.100.105': NOW + 100, '198.51.100.104': NOW + 100}))
    peers = stamper.compile_peers(paths, _policy_result(doc), 'device-1', 'edge',
                                  True, definition, NOW, NOW + 600)
    assert peers['mode'] == 'allow'
    assert ('192.0.2.86' in peers['allowed']) is origin
    # Exercise the shipped agent parser in its normal isolated import layout.
    code = """import sys,json
sys.path[:0]=sys.argv[1:]
import iris_agent
value=iris_agent._peer_blocklist({'effective_peers':json.load(sys.stdin)},
                                {'catalog_url':'https://192.0.2.240:8443'})
print(json.dumps(value))
"""
    process = subprocess.run([sys.executable, '-I', '-B', '-c', code,
                              str(REPO / 'device/agent'), str(REPO / 'device')],
                             input=json.dumps(peers), text=True, capture_output=True,
                             check=True, timeout=20)
    rules, degraded = json.loads(process.stdout)
    assert degraded is False
    networks = [ipaddress.ip_network(rule) for rule in rules]
    blocked = lambda value: any(ipaddress.ip_address(value) in network for network in networks)
    assert blocked('192.0.2.86') is not origin
    assert blocked('192.0.2.240') is not origin
    assert blocked('198.51.100.104') is False
    assert blocked('192.0.2.87') is True


@pytest.mark.parametrize('value', ['0.0.0.0/0', '192.0.2.86/32', 'localhost', '::1',
    '0.0.0.0', '127.0.0.1', '169.254.1.1', '224.0.0.1', '255.255.255.255',
    '192.0.2.86,', '192.0.2.86,192.0.2.86', ' 192.0.2.86',
    ','.join('192.0.2.' + str(i) for i in range(1, 10))])
def test_invalid_origin_declaration_never_emits_permissive_posture(tmp_path, monkeypatch, value):
    monkeypatch.setenv('IRIS_ORIGIN_EGRESS_IPS', value)
    paths, *_ = _setup(tmp_path)
    doc, definition = policy()
    with pytest.raises(stamper.StamperError, match='origin_egress_invalid'):
        stamper.compile_peers(paths, _policy_result(doc), 'device-1', 'edge',
                             True, definition, NOW, NOW + 600)


def test_origin_cannot_overflow_allow_list_into_tracker_only(tmp_path, monkeypatch):
    monkeypatch.setenv('IRIS_ORIGIN_EGRESS_IPS', '192.0.2.86')
    monkeypatch.setattr(instructions, 'MAX_ALLOWED', 1)
    paths, *_ = _setup(tmp_path)
    doc, definition = policy()
    with pytest.raises(stamper.StamperError, match='origin_egress_invalid'):
        stamper.compile_peers(paths, _policy_result(doc), 'device-1', 'edge',
                             True, definition, NOW, NOW + 600)


def test_origin_change_reissues_authenticated_part_without_policy_edit(tmp_path, monkeypatch):
    monkeypatch.setenv('IRIS_ORIGIN_EGRESS_IPS', '192.0.2.86')
    paths, _fleet, catalog, producer, *_ = _setup(tmp_path)
    doc, _ = policy()
    _write_policy(paths, doc)
    assert producer.stamp_device('device-1') == 'updated'
    first = copy.deepcopy(_raw_stamp(catalog))
    assert '192.0.2.86' in first['part']['peers']['allowed']
    monkeypatch.setenv('IRIS_ORIGIN_EGRESS_IPS', '192.0.2.87')
    assert producer.stamp_device('device-1') == 'updated'
    second = _raw_stamp(catalog)
    instructions.validate_stamp(second)
    assert second['policy_revision'] == first['policy_revision']
    assert second['instr_serial'] == first['instr_serial'] + 1
    assert '192.0.2.86' not in second['part']['peers']['allowed']
    assert '192.0.2.87' in second['part']['peers']['allowed']
    assert producer.stamp_device('device-1') == 'unchanged'


@pytest.mark.parametrize('addresses', [[], ['192.0.2.86'], ['192.0.2.86', '192.0.2.87']])
def test_cli_setup_and_closed_topology_validators_preserve_addresses(monkeypatch, addresses):
    fake_files(monkeypatch)
    for command in ('install', 'setup'):
        argv = [command]
        for address in addresses:
            argv.extend(['--origin-egress-ip', address])
        args = cli.parser().parse_args(argv)
        assert args.origin_egress_ip == addresses
        if command == 'setup':
            assert cli.parser().parse_args(local_setup.install_arguments(args)).origin_egress_ip == addresses
    for factory, validator in ((docker_config, deploy.validate_config),
                               (kube_config, kube_deploy.validate_config),
                               (split_config, split_deploy.validate_split_config)):
        value = dict(factory(), origin_egress_ips=addresses)
        before = copy.deepcopy(value)
        validator(value)
        deploy.validate_config(value)
        assert value == before


@pytest.mark.parametrize('addresses', [None, '192.0.2.86', [None], ['0.0.0.0/0'],
    ['127.0.0.1'], ['192.0.2.86', '192.0.2.86'], ['192.0.2.1'] * 9])
def test_installer_rejects_invalid_origin_before_mutation(addresses):
    with pytest.raises(InstallError, match='Origin egress'):
        deploy.validate_config(dict(docker_config(), origin_egress_ips=addresses))
