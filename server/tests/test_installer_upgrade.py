# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Managed upgrade contract tests; not live deployment qualification."""

import copy
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'tools'))
from iris_installer import upgrade_plan as plan
from iris_installer.state import InstallError

ID = 'fef3a99c-32dc-49bb-88ef-bd2e6397aed7'
OPERATION = 'bdc3d313-2612-43ec-92df-0e10b83b2cf8'
IMAGES = {'iris': 'sha256:' + '1' * 64, 'console': 'sha256:' + '2' * 64}


def compose():
    return {'name': 'iris-owned', 'services': {
        name: {'image': 'old-' + name, 'build': {'context': '/old/source', 'dockerfile': name + '/Dockerfile'},
               'environment': {'CREDENTIAL_FILE': '/existing/encrypted.age'}, 'restart': 'unless-stopped',
               'volumes': [{'source': 'existing-' + name, 'target': '/state'}],
               'ports': [{'host_ip': '127.0.0.1', 'published': str(8080 + index), 'target': 8080}],
               'user': '10001:10001', 'cap_drop': ['ALL']}
        for index, name in enumerate(plan.SERVICES)},
        'volumes': {'existing-iris': {'name': 'owned-server-volume'}},
        'networks': {'default': {'name': 'owned-network'}}}


def journal():
    return {'schema': 1, 'id': ID, 'config': {'target': 'docker', 'instance': 'iris-owned',
            'recovery_recipient': 'existing-recipient', 'image_root': '/existing/images'},
            'source_manifest': {'server/code.py': '3' * 64},
            'root_digests': {'root-a.pub': '4' * 64, 'root-b.pub': '5' * 64},
            'completed': {'prepared': '6' * 64, 'images': {'old': 'sha256:' + '7' * 64},
                'packages': {name: '8' * 64 for name in plan.NATIVE_FILES},
                'signing': True, 'guestshell': {'state': 'ok'}, 'other': {'keep': True}},
            'state': 'PRODUCTION_REVIEW_REQUIRED', 'arbitrary_recorded_authority': {'epoch': 43}}


@pytest.mark.parametrize('bad', [None, '', '../source', 'Fef3a99c-32dc-49bb-88ef-bd2e6397aed7'])
def test_upgrade_id_refuses_ambiguous_authority(bad):
    with pytest.raises(InstallError):
        plan.identifier(bad)


@pytest.mark.parametrize('bad', [{}, {'../escape': 'a' * 64}, {'/absolute': 'a' * 64},
                              {'a\nline': 'a' * 64}, {'a//b': 'a' * 64}, {'valid': 'A' * 64}])
def test_upgrade_file_manifest_is_closed(bad):
    with pytest.raises(InstallError):
        plan.file_manifest(bad)


def test_upgrade_template_change_refuses_without_mutating_inputs():
    previous = compose(); changed = copy.deepcopy(previous)
    changed['services']['iris']['volumes'].append({'source': '/unreviewed', 'target': '/new'})
    before = copy.deepcopy(previous)
    with pytest.raises(InstallError, match='runtime layout'):
        plan.candidate_compose(previous, previous, changed, IMAGES)
    assert previous == before


def test_upgrade_preserves_current_credential_environment_and_storage():
    old = compose(); new = copy.deepcopy(old)
    new['services']['iris']['image'] = 'new-image'
    new['services']['iris']['build']['context'] = '/new/source'
    live = copy.deepcopy(old)
    live['services']['iris']['environment']['CURRENT_ROTATED_CERTIFICATE'] = '/existing/rotated.pem'
    live_before = copy.deepcopy(live)
    result = plan.candidate_compose(live, old, new, IMAGES)
    assert live == live_before
    for name in plan.SERVICES:
        expected = copy.deepcopy(live['services'][name])
        expected.pop('build'); expected.update(image=IMAGES[name], pull_policy='never')
        assert result['services'][name] == expected
    assert result['volumes'] == live['volumes'] and result['networks'] == live['networks']
    starting = plan.startup_compose(result)
    assert all(row['restart'] == 'no' for row in starting['services'].values())
    assert all(row['restart'] == 'unless-stopped' for row in result['services'].values())


@pytest.mark.parametrize('change', ['kubernetes', 'docker-split', 'prebuilt', 'partial', 'root'])
def test_upgrade_rejects_unsupported_or_incomplete_install(change):
    value = journal()
    if change in ('kubernetes', 'docker-split'): value['config']['target'] = change
    elif change == 'prebuilt': value['input_selection'] = {'kit': {}}
    elif change == 'partial': value['completed'].pop('guestshell')
    else: value['root_digests']['root-a.pub'] = 'invalid'
    with pytest.raises(InstallError):
        plan.require_source_build(value)


def test_upgrade_next_generation_only_changes_code_checkpoints():
    original = journal(); untouched = copy.deepcopy(original)
    template = compose(); final = plan.candidate_compose(template, template, template, IMAGES)
    source = {'server/code.py': '9' * 64}; packages = {name: 'a' * 64 for name in plan.NATIVE_FILES}
    result = plan.next_journal(original, operation_id=OPERATION, source=source,
                               compose=final, packages=packages, guestshell={'state': 'ok', 'sha256': 'b' * 64})
    assert original == untouched
    for name in ('id', 'config', 'root_digests', 'arbitrary_recorded_authority'):
        assert result[name] == original[name]
    assert result['completed']['signing'] is True and result['completed']['other'] == {'keep': True}
    assert result['completed']['images'] == {image: image for image in IMAGES.values()}
    assert result['source_manifest'] == source and result['completed']['packages'] == packages
    assert result['application_upgrades'][0]['operation_id'] == OPERATION
    assert result['completed']['prepared'] == plan.fingerprint(final)


def test_upgrade_requires_real_new_source_and_served_readiness():
    original = journal(); template = compose()
    final = plan.candidate_compose(template, template, template, IMAGES)
    args = dict(operation_id=OPERATION, source=original['source_manifest'],
                compose=final, packages=original['completed']['packages'], guestshell={'state': 'ok'})
    with pytest.raises(InstallError, match='already installed'):
        plan.next_journal(original, **args)
    args.update(source={'new.py': 'a' * 64}, guestshell={'state': 'unknown'})
    with pytest.raises(InstallError, match='verified served'):
        plan.next_journal(original, **args)
