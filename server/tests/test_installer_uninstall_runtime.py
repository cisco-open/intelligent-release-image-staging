# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Real topology selector code with isolated Docker/Kubernetes transports."""

import copy
import json
from pathlib import Path
import sys
from types import SimpleNamespace
import uuid

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'tools'))
from iris_installer import uninstall_docker as docker, uninstall_runtime as runtime
from iris_installer import uninstall, managed_worker
from iris_installer.state import InstallError, atomic_write


class DockerEngine:
    def __init__(self):
        self.identity = str(uuid.uuid4())
        labels = {'com.cisco.iris.installer': self.identity, 'com.docker.compose.project': 'iris-owned'}
        self.rows = {
            'container': {'a' * 64: {'Id': 'a' * 64, 'Name': '/iris-server', 'Image': 'sha256:' + '1' * 64,
                'Config': {'Labels': dict(labels, **{'com.docker.compose.service': 'iris'}), 'Env': ['SECRET=not-output']},
                'HostConfig': {'RestartPolicy': {'Name': 'unless-stopped'}}, 'Mounts': [],
                'State': {'Running': True, 'ExitCode': 0, 'OOMKilled': False}}},
            'network': {'b' * 64: {'Id': 'b' * 64, 'Name': 'iris-net', 'Labels': labels, 'Containers': {'a' * 64: {}}, 'Driver': 'bridge',
                'IPAM': {'Driver': 'default', 'Options': None, 'Config': [{'Subnet': '172.18.0.0/16', 'Gateway': '172.18.0.1'}]},
                'Status': {'IPAM': {'Subnets': {'172.18.0.0/16': {'IPsInUse': 4, 'DynamicIPsAvailable': 65532}}}}}},
            'volume': {'iris-data': {'Name': 'iris-data', 'Labels': labels, 'Driver': 'local', 'Options': {},
                                     'Mountpoint': '/var/lib/docker/volumes/iris-data/_data', 'CreatedAt': 'original'}}}
        self.calls = []
        self.request = {'project': 'iris-owned', 'instance_id': self.identity, 'names': {
            'container': {'iris-server': {'service': 'iris', 'image': 'sha256:' + '1' * 64}},
            'network': {'iris-net': {}}, 'volume': {'iris-data': {}}}}

    def run(self, argv):
        self.calls.append(argv)
        if argv[:2] == ['docker', 'info']:
            return json.dumps('engine-original').encode()
        if argv[:2] == ['docker', 'update']:
            self.rows['container'][argv[-1]]['HostConfig']['RestartPolicy'] = {'Name': 'no'}
            return b''
        if argv[:2] == ['docker', 'stop']:
            self.rows['container'][argv[-1]]['State']['Running'] = False
            for row in self.rows['network'].values():
                if row['Containers'].pop(argv[-1], None) is not None:
                    counts = row['Status']['IPAM']['Subnets']['172.18.0.0/16']
                    counts['IPsInUse'] -= 1
                    counts['DynamicIPsAvailable'] += 1
            return b''
        _, kind, verb, *rest = argv
        if verb == 'ls':
            rows = self.rows[kind]
            if '--filter' in rest:
                rows = {key: row for key, row in rows.items() if
                    (row.get('Config', {}).get('Labels', {}) if kind == 'container' else row.get('Labels', {}))
                    .get('com.docker.compose.project') == 'iris-owned'}
            return ('\n'.join(rows) + '\n').encode()
        if verb == 'inspect':
            return json.dumps([self.rows[kind][rest[0]]]).encode()
        assert verb == 'rm' and len(rest) == 1
        del self.rows[kind][rest[0]]
        if kind == 'container':
            for row in self.rows['network'].values():
                row['Containers'].pop(rest[0], None)
        return b''


def test_docker_exact_ids_clean_stop_and_no_secret_output():
    engine = DockerEngine()
    observed = docker.perform(engine.request, engine.run)
    assert 'not-output' not in json.dumps(observed)
    stopped = docker.perform(dict(engine.request, action='stop', key='container/iris-server',
                                  expected=docker.stable(observed)), engine.run)
    assert not stopped['resources']['container/iris-server']['running']
    for key in ('container/iris-server', 'network/iris-net', 'volume/iris-data'):
        stopped = docker.perform(dict(engine.request, action='remove', key=key,
                                      expected=docker.stable(stopped)), engine.run)
    assert stopped['resources'] == {}
    assert [row for row in engine.calls if row[2:3] == ['rm']] == [
        ['docker', 'container', 'rm', 'a' * 64], ['docker', 'network', 'rm', 'b' * 64],
        ['docker', 'volume', 'rm', 'iris-data']]
    assert not any('--force' in row or 'prune' in row or 'down' in row for row in engine.calls)


@pytest.mark.parametrize('change', ['owner', 'project', 'image', 'extra-resource', 'foreign-network', 'foreign-volume', 'foreign-bind', 'volume-options'])
def test_docker_foreign_or_changed_resources_are_never_removal_targets(change):
    engine = DockerEngine()
    expected = docker.stable(docker.perform(engine.request, engine.run))
    container = engine.rows['container']['a' * 64]
    if change == 'owner':
        container['Config']['Labels']['com.cisco.iris.installer'] = str(uuid.uuid4())
    elif change == 'project':
        container['Config']['Labels']['com.docker.compose.project'] = 'another'
    elif change == 'image':
        container['Image'] = 'sha256:' + 'f' * 64
    elif change == 'extra-resource':
        row = copy.deepcopy(container)
        row.update(Id='c' * 64, Name='/other')
        engine.rows['container']['c' * 64] = row
    elif change == 'foreign-network':
        engine.rows['network']['b' * 64]['Containers']['c' * 64] = {}
    elif change in ('foreign-volume', 'foreign-bind'):
        row = copy.deepcopy(container)
        row.update(Id='c' * 64, Name='/foreign')
        row['Config']['Labels'] = {}
        row['Mounts'] = [{'Name': 'iris-data'}] if change == 'foreign-volume' else [
            {'Type': 'bind', 'Source': '/var/lib/docker/volumes/iris-data/_data/nested', 'RW': False}]
        engine.rows['container']['c' * 64] = row
    else:
        engine.rows['volume']['iris-data']['Options'] = {'device': '/somewhere'}
    before = len(engine.calls)
    with pytest.raises(ValueError):
        docker.perform(dict(engine.request, action='remove', key='volume/iris-data', expected=expected), engine.run)
    assert not any(row[2:3] == ['rm'] for row in engine.calls[before:])


def test_docker_running_container_blocks_removal():
    engine = DockerEngine()
    expected = docker.stable(docker.perform(engine.request, engine.run))
    with pytest.raises(ValueError):
        docker.perform(dict(engine.request, action='remove', key='container/iris-server', expected=expected), engine.run)


def test_docker_network_runtime_status_changes_on_owned_clean_stop():
    # This is the real Docker inspect shape observed at the live refusal. Only
    # the transport is modeled; the shipped inventory/stop engine is exercised.
    engine = DockerEngine()
    before = docker.perform(engine.request, engine.run)
    stopped = docker.perform(dict(engine.request, action='stop', key='container/iris-server',
                                  expected=docker.stable(before)), engine.run)
    assert docker.stable(stopped) == docker.stable(before)
    assert engine.rows['network']['b' * 64]['Status']['IPAM']['Subnets']['172.18.0.0/16'] == {
        'IPsInUse': 3, 'DynamicIPsAvailable': 65533}
    assert not stopped['resources']['container/iris-server']['running']


@pytest.mark.parametrize('change', ['driver', 'options', 'ipam-config', 'unknown-status', 'unknown-subnet-field', 'subnet-key'])
def test_docker_network_configuration_and_unknown_status_are_still_pinned(change):
    engine = DockerEngine()
    expected = docker.stable(docker.perform(engine.request, engine.run))
    row = engine.rows['network']['b' * 64]
    if change == 'driver': row['Driver'] = 'overlay'
    elif change == 'options': row['Options'] = {'unexpected': 'changed'}
    elif change == 'ipam-config': row['IPAM']['Config'][0]['Gateway'] = '172.18.0.2'
    elif change == 'unknown-status': row['Status']['Unexpected'] = 'changed'
    elif change == 'unknown-subnet-field': row['Status']['IPAM']['Subnets']['172.18.0.0/16']['Unexpected'] = 'changed'
    else: row['Status']['IPAM']['Subnets']['192.0.2.0/24'] = row['Status']['IPAM']['Subnets'].pop('172.18.0.0/16')
    before = len(engine.calls)
    with pytest.raises(ValueError):
        docker.perform(dict(engine.request, action='stop', key='container/iris-server', expected=expected), engine.run)
    assert not any(call[:2] in (['docker', 'update'], ['docker', 'stop']) for call in engine.calls[before:])


@pytest.mark.parametrize('bad', [None, True, -1, 1.5, '4', 2**128 + 1])
def test_docker_network_status_counter_types_refuse_before_mutation(bad):
    engine = DockerEngine()
    engine.rows['network']['b' * 64]['Status']['IPAM']['Subnets']['172.18.0.0/16']['IPsInUse'] = bad
    with pytest.raises(ValueError): docker.perform(engine.request, engine.run)
    assert not any(call[:2] in (['docker', 'update'], ['docker', 'stop']) for call in engine.calls)


def test_historical_network_status_fingerprint_is_not_silently_adopted():
    engine = DockerEngine()
    expected = docker.stable(docker.perform(engine.request, engine.run))
    row = engine.rows['network']['b' * 64]
    # Retained plans made by the old producer included these runtime counters.
    expected['resources']['network/iris-net']['sha256'] = docker.digest({
        key: value for key, value in row.items() if key != 'Containers'})
    before = len(engine.calls)
    with pytest.raises(ValueError):
        docker.perform(dict(engine.request, action='stop', key='container/iris-server', expected=expected), engine.run)
    assert not any(call[:2] in (['docker', 'update'], ['docker', 'stop']) for call in engine.calls[before:])


class Cluster:
    def __init__(self, tmp_path):
        from iris_installer.kube_deploy import LABEL
        self.identity = str(uuid.uuid4())
        self.rows, self.calls, self.pods, self.rs = {}, [], [], []
        desired = []
        for kind, name in [('Namespace', 'iris-owned'), ('Deployment', 'iris-seed-server'),
                           ('PersistentVolumeClaim', 'iris-data'), ('Secret', 'iris-age')]:
            row = {'apiVersion': 'apps/v1' if kind == 'Deployment' else 'v1', 'kind': kind,
                   'metadata': {'name': name, 'labels': {LABEL: self.identity}}}
            if kind == 'Deployment':
                row['spec'] = {'replicas': 0, 'template': {'spec': {'containers': [
                    {'name': 'iris', 'image': 'example.invalid/iris@sha256:' + 'a' * 64}]}}}
            if kind == 'Secret':
                row['data'] = {'identity': 'sensitive-not-output'}
            desired.append(copy.deepcopy(row))
            row['metadata'].update(uid=str(uuid.uuid4()), resourceVersion='7')
            self.rows[kind + '/' + name] = row
        self.manifest_file = tmp_path / 'kube.json'
        atomic_write(self.manifest_file, json.dumps(desired).encode())
        self.config = {'target': 'kubernetes', 'kube_namespace': 'iris-owned'}
        self.cluster = {'uid': str(uuid.uuid4()), 'server': 'https://example.invalid', 'context': 'owned'}
        self.journal = SimpleNamespace(document={'id': self.identity, 'completed': {'kube-cluster': self.cluster}})
        self.request = {'cluster': self.cluster, 'manifest_sha256': runtime.deploy.digest(self.manifest_file),
                        'resources': {key: {'id': row['metadata']['uid']} for key, row in self.rows.items()}}
        self.adapter = runtime.Kubernetes(self, self.request)

    def cluster_preflight(self):
        pass

    def get(self, kind, name):
        return copy.deepcopy(self.rows.get(kind + '/' + name))

    def kube(self, *argv, **kwargs):
        self.calls.append((argv, kwargs))
        if argv[0] == 'get':
            if argv[1] == 'pods':
                rows = self.pods
            elif argv[1] == 'replicasets':
                rows = self.rs
            else:
                rows = [row for key, row in self.rows.items() if key.startswith(argv[1] + '/')]
            return json.dumps({'items': rows}).encode()
        assert argv[:2] == ('delete', '--raw')
        options = json.loads(kwargs['input'])
        assert options['propagationPolicy'] == 'Foreground'
        uid = options['preconditions']['uid']
        key, = [key for key, row in self.rows.items() if row['metadata']['uid'] == uid]
        assert options['preconditions']['resourceVersion'] == self.rows[key]['metadata']['resourceVersion']
        del self.rows[key]
        return b''


def test_kubernetes_uid_precondition_secret_purge_and_namespace_preservation(tmp_path):
    cluster = Cluster(tmp_path)
    observed = cluster.adapter.snapshot()
    assert 'sensitive-not-output' not in json.dumps(observed)
    for key in runtime.targets('kubernetes', observed, True):
        observed = cluster.adapter.remove(key, cluster.adapter.stable(observed))
    assert set(observed['resources']) == {'Namespace/iris-owned'}
    deletions = [args[2] for args, _ in cluster.calls if args[0] == 'delete']
    assert all('/namespaces/iris-owned/' in path for path in deletions)
    assert not any(path.endswith('/namespaces/iris-owned') for path in deletions)


@pytest.mark.parametrize('change', ['uid', 'secret', 'cluster', 'foreign-pod', 'extra-owned-resource'])
def test_kubernetes_foreign_or_drifted_targets_refuse(tmp_path, change):
    from iris_installer.kube_deploy import LABEL
    cluster = Cluster(tmp_path)
    original = cluster.adapter.stable(cluster.adapter.snapshot())
    if change == 'uid':
        cluster.rows['Secret/iris-age']['metadata']['uid'] = str(uuid.uuid4())
    elif change == 'secret':
        cluster.rows['Secret/iris-age']['data']['identity'] = 'changed'
    elif change == 'cluster':
        cluster.request['cluster'] = dict(cluster.cluster, uid=str(uuid.uuid4()))
    elif change == 'foreign-pod':
        cluster.pods = [{'metadata': {'uid': 'foreign', 'labels': {}}, 'spec': {
            'volumes': [{'persistentVolumeClaim': {'claimName': 'iris-data'}}]}}]
    else:
        cluster.rows['Secret/another'] = {'kind': 'Secret', 'metadata': {'name': 'another', 'labels': {LABEL: cluster.identity}}}
    with pytest.raises(InstallError):
        cluster.adapter.remove('Secret/iris-age', original)
    assert not any(args[0] == 'delete' for args, _ in cluster.calls)


def test_kubernetes_foreground_marker_is_only_expected_hash_variation(tmp_path):
    cluster = Cluster(tmp_path)
    row = cluster.rows['Deployment/iris-seed-server']
    before = runtime.kube_fingerprint(row)
    row['metadata'].update(deletionTimestamp='now', finalizers=['foregroundDeletion'])
    assert runtime.kube_fingerprint(row) == before
    row['metadata']['finalizers'].append('unknown')
    assert runtime.kube_fingerprint(row) != before


@pytest.mark.parametrize('fields', [
    b'ActiveState=active\nUnitFileState=disabled\nMainPID=100\n',
    b'ActiveState=inactive\nUnitFileState=enabled\nMainPID=0\n',
    b'ActiveState=inactive\nUnitFileState=disabled\nMainPID=100\n'])
def test_worker_fence_requires_disabled_unit_and_no_main_process(monkeypatch, fields):
    monkeypatch.setattr(managed_worker, 'command', lambda *_args, **_kwargs: fields)
    with pytest.raises(InstallError, match='disabled and stopped'):
        uninstall.worker_stopped({'record': {'unit': 'owned.service'}})
