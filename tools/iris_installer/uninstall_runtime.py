# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Topology-specific inventory and exact removal for scoped uninstall."""

import copy
import hashlib
import json
from pathlib import Path
import shlex
import time

from . import deploy, uninstall_docker
from .state import InstallError, regular_bytes
from .upgrade_plan import canonical, require


def fingerprint(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def names(install, remote=False):
    path = install.console_file if remote else install.compose_file
    document = json.loads(regular_bytes(path))
    completed = install.journal.document['completed']
    key = 'console-prepared' if remote else 'prepared'
    require(deploy.digest(path) == completed.get(key), 'Uninstall configuration changed')
    images = completed.get('images', {})
    if remote:
        images = {spec['image']: completed['console-image'] for spec in document['services'].values()}
    result = {'container': {}, 'volume': {}, 'network': {}}
    for service, spec in document['services'].items():
        require(service in ('iris', 'console') and spec['image'] in images, 'Uninstall service image is not recorded')
        result['container'][spec['container_name']] = {'image': images[spec['image']], 'service': service}
    for kind in ('volume', 'network'):
        for logical, spec in document.get(kind + 's', {}).items():
            require(not spec.get('external'), 'External Docker resources are not uninstall targets')
            name = spec.get('name') or install.config['instance'] + '_' + logical
            result[kind][name] = {}
    return result


class Docker:
    def __init__(self, install, request, remote=False):
        self.install, self.request, self.remote = install, request, remote

    def call(self, action='inspect', **values):
        request = dict(self.request, action=action, **values)
        try:
            if not self.remote:
                return uninstall_docker.perform(request, lambda argv: self.install.command(argv, capture=True, timeout=210))
            expected = self.install.journal.document['completed'].get('split-transport')
            require(expected and self.install.transport_fingerprints() == expected,
                    'Pinned Console SSH transport changed')
            source = regular_bytes(Path(uninstall_docker.__file__), 128 * 1024).decode()
            command = ('sudo -n env -i PATH=/usr/bin:/bin python3 -I -B -c ' + shlex.quote(source))
            raw = self.install.command(self.install.ssh_command(command), input=canonical(request),
                                       capture=True, timeout=240)
            return json.loads(raw)
        except (ValueError, KeyError, TypeError):
            raise InstallError('Exact Docker uninstall inventory changed; preserve the operation') from None

    def snapshot(self):
        return self.call()

    def stable(self, value):
        return uninstall_docker.stable(value)

    def remove(self, key, expected):
        return self.call('remove', key=key, expected=expected)

    def stop(self, key, expected):
        return self.call('stop', key=key, expected=expected)


def kube_fingerprint(row):
    value = {key: copy.deepcopy(item) for key, item in row.items() if key != 'status'}
    metadata = value['metadata']
    if metadata.get('deletionTimestamp') and 'foregroundDeletion' in metadata.get('finalizers', []):
        metadata['finalizers'].remove('foregroundDeletion')
        if not metadata['finalizers']:
            metadata.pop('finalizers')
    for key in ('resourceVersion', 'managedFields', 'creationTimestamp', 'generation', 'deletionTimestamp', 'deletionGracePeriodSeconds'):
        metadata.pop(key, None)
    return fingerprint(value)


class Kubernetes:
    def __init__(self, install, request):
        self.install, self.request = install, request

    def snapshot(self):
        from .kube_deploy import LABEL, _contains
        install, request = self.install, self.request
        install.cluster_preflight()
        require(install.journal.document['completed']['kube-cluster'] == request['cluster'],
                'Uninstall Kubernetes cluster changed')
        require(deploy.digest(install.manifest_file) == request['manifest_sha256'],
                'Uninstall Kubernetes manifest changed')
        manifests = json.loads(regular_bytes(install.manifest_file, 8 * 1024 * 1024))
        desired = {row['kind'] + '/' + row['metadata']['name']: row for row in manifests}
        require(set(desired) == set(request['resources']), 'Uninstall resource set changed')
        result = {}
        for key, saved in request['resources'].items():
            kind, name = key.split('/', 1)
            row = install.get(kind, name)
            if row is None:
                continue
            require(row['metadata']['uid'] == saved['id'] and _contains(row, desired[key]),
                    'Uninstall Kubernetes UID or specification changed')
            require(row['metadata'].get('labels', {}).get(LABEL) == install.journal.document['id'],
                    'Uninstall Kubernetes ownership changed')
            result[key] = {'id': row['metadata']['uid'], 'sha256': kube_fingerprint(row),
                           'version': row['metadata']['resourceVersion'],
                           'deleting': bool(row['metadata'].get('deletionTimestamp'))}
        for kind in {key.split('/')[0] for key in desired} - {'Namespace'}:
            rows = json.loads(install.kube('get', kind, '-l', LABEL + '=' + install.journal.document['id'],
                                           '-o', 'json', capture=True))['items']
            require(all(kind + '/' + row['metadata']['name'] in desired for row in rows),
                    'An unrecorded Kubernetes resource claims this installation')
        # Never delete a namespace. Foreign occupants survive; a foreign writer
        # of the owned PVC is a refusal even when the PVC will be retained.
        pods = json.loads(install.kube('get', 'pods', '-o', 'json', capture=True))['items']
        owned_pods = []
        replicasets = json.loads(install.kube('get', 'replicasets', '-o', 'json', capture=True))['items']
        deployments = {saved['id'] for key, saved in request['resources'].items() if key.startswith('Deployment/')}
        owned_rs = {row['metadata']['uid'] for row in replicasets if any(
            owner.get('uid') in deployments and owner.get('controller') is True
            for owner in row['metadata'].get('ownerReferences', []))}
        for pod in pods:
            labels = pod['metadata'].get('labels', {})
            uses_data = any(v.get('persistentVolumeClaim', {}).get('claimName') == 'iris-data'
                            for v in pod.get('spec', {}).get('volumes', []))
            owned = labels.get(LABEL) == install.journal.document['id'] and any(
                owner.get('uid') in owned_rs and owner.get('controller') is True
                for owner in pod['metadata'].get('ownerReferences', []))
            require(not (uses_data or labels.get(LABEL) == install.journal.document['id']) or owned,
                    'An unrecorded Kubernetes pod can access this deployment')
            if owned:
                owned_pods.append(pod['metadata']['uid'])
        return {'cluster': request['cluster'], 'resources': result, 'pods': sorted(owned_pods)}

    def stable(self, value):
        return {'cluster': value['cluster'], 'resources': {
            key: {name: row[name] for name in ('id', 'sha256')}
            for key, row in value['resources'].items()}}

    def remove(self, key, expected):
        from .kube_deploy import RESOURCE_NAMES
        current = self.snapshot()
        require(self.stable(current) == expected, 'Kubernetes uninstall preimage changed')
        kind, name = key.split('/', 1)
        require(kind != 'Namespace' and key in current['resources'], 'Namespace removal is not authorized')
        if kind not in ('Deployment', 'Service'):
            require(not current['pods'], 'Wait for all owned pods to terminate before data or configuration removal')
        row = current['resources'][key]
        version = 'apps/v1' if kind == 'Deployment' else 'networking.k8s.io/v1' if kind == 'NetworkPolicy' else 'v1'
        prefix = '/apis/' + version if '/' in version else '/api/' + version
        endpoint = prefix + '/namespaces/' + self.install.config['kube_namespace'] + '/' + RESOURCE_NAMES[kind] + '/' + name
        if not row['deleting']:
            options = {'apiVersion': 'v1', 'kind': 'DeleteOptions', 'propagationPolicy': 'Foreground',
                       'preconditions': {'uid': row['id'], 'resourceVersion': row['version']}}
            self.install.kube('delete', '--raw', endpoint, '-f', '-', input=canonical(options), timeout=210)
        deadline = time.monotonic() + 210
        while True:
            after = self.snapshot()
            if key not in after['resources']:
                wanted = copy.deepcopy(expected)
                del wanted['resources'][key]
                require(self.stable(after) == wanted, 'Kubernetes uninstall changed another resource')
                return after
            require(after['resources'][key]['id'] == row['id'], 'Kubernetes resource was replaced during deletion')
            require(time.monotonic() < deadline, 'Kubernetes deletion is still pending; recover this operation')
            time.sleep(1)


def discover(install):
    install.verify_inputs()
    install.verify_resource_ownership()
    if install.config['target'] == 'kubernetes':
        from .kube_deploy import _contains
        manifests = install.manifests()
        resources = {}
        for desired in manifests:
            key = desired['kind'] + '/' + desired['metadata']['name']
            saved = install.journal.document['completed']['kube-resources'].get(key)
            row = install.get(desired['kind'], desired['metadata']['name'])
            require(saved and row and saved['uid'] == row['metadata']['uid'] and _contains(row, desired),
                    'Uninstall needs every exact recorded Kubernetes resource')
            resources[key] = {'id': saved['uid']}
        request = {'resources': resources, 'cluster': install.journal.document['completed']['kube-cluster'],
                   'manifest_sha256': deploy.digest(install.manifest_file)}
        return {'kubernetes': request}
    # Reuse the existing exact local mounts, immutable images and foreign
    # writer checks. This path does not capture data or export image archives.
    from .backup import docker_capture_plan
    if install.config['target'] == 'docker-split':
        install.capture_plan()
    else:
        docker_capture_plan(install)
    result = {}
    for location in (('local', 'console') if install.config['target'] == 'docker-split' else ('local',)):
        request = {'project': install.config['instance'], 'instance_id': install.journal.document['id'],
                   'names': names(install, remote=location == 'console')}
        if location == 'console':
            request['root'] = install.config['console_state_dir']
        result[location] = request
    return result


def driver(install, location, request):
    return Kubernetes(install, request) if location == 'kubernetes' else Docker(install, request, location == 'console')


def kube_fence_authority(install):
    return install.capture_recovery_authority([], {}) if install.config['target'] == 'kubernetes' else None


def check_kube_fence_journal(install, original, authority, *, recover=True):
    """Only the existing exact-ID scale/maintenance-helper transaction may vary."""
    before, after = copy.deepcopy(original), copy.deepcopy(install.journal.document)
    for value in (before, after):
        value.pop('state', None)
        for name in ('kube-manifests', 'kube-resources', 'kube-helper', 'kube-clean-stop'):
            value['completed'].pop(name, None)
    require(before == after, 'Uninstall writer fence changed unrelated installation authority')
    # Existing recovery validates pending updates as replicas-only changes,
    # preserves every original UID and normalized declaration, and admits only
    # the producer's exact deny-all maintenance policy addition.
    if recover:
        install.capture_recovery_inventory(authority)
    else:
        require(install.capture_recovery_authority([], {}) == authority,
                'Uninstall stopped Kubernetes declarations changed')


def fence_kubernetes(install, original, authority):
    from . import backup, upgrade_runtime
    check_kube_fence_journal(install, original, authority)
    containers = [{'id': row['uid'], 'service': service} for service, row in (
        ('console', original['completed']['kube-resources']['Deployment/iris-console']),
        ('iris', original['completed']['kube-resources']['Deployment/iris-seed-server']))]
    backup.stop_writers(install, containers, recovering_clean_operation=True)
    install.assert_writers_stopped()
    upgrade_runtime.drain(install, stopped=True)
    install.maintenance_close()
    check_kube_fence_journal(install, original, authority)
    return discover(install)


def targets(location, snapshot, purge):
    resources = snapshot['resources']
    if location == 'kubernetes':
        # Never cascade-delete the namespace. Deployment credential Secrets
        # survive by default and require the same explicit data-purge choice.
        kinds = ['Deployment', 'Service', 'ConfigMap', 'NetworkPolicy']
        if purge:
            kinds.extend(('PersistentVolumeClaim', 'Secret'))
    else:
        kinds = ['container', 'network'] + (['volume'] if purge else [])
    return [key for kind in kinds for key in sorted(resources) if key.startswith(kind + '/')]
