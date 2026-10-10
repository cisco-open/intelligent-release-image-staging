# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Managed upgrade contract tests; not live deployment qualification."""

import copy
from pathlib import Path
import sys
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'tools'))
from iris_installer import upgrade_plan as plan
from iris_installer import prebuilt_install, release_kit
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


def test_upgrade_accepts_actual_source_install_selection_without_changing_it(tmp_path):
    value = journal()
    value.update(prebuilt_install.prepare_selection(SimpleNamespace(), value['source_manifest'], tmp_path))
    assert value['input_selection'] == {'schema': 'iris-install-input-v1', 'mode': 'source'}
    original = copy.deepcopy(value)
    plan.require_source_build(value)
    final = plan.candidate_compose(compose(), compose(), compose(), IMAGES)
    result = plan.next_journal(value, operation_id=OPERATION, source={'new.py': 'a' * 64},
                              compose=final, packages=value['completed']['packages'],
                              guestshell={'state': 'ok'})
    assert value == original
    assert result['input_selection'] == original['input_selection']


def test_upgrade_accepts_legacy_source_journal_without_selection():
    value = journal(); original = copy.deepcopy(value)
    plan.require_source_build(value)
    assert value == original and 'input_selection' not in value


def test_upgrade_rejects_valid_prebuilt_selection(tmp_path):
    kit = release_kit.VerifiedKit(tmp_path, 'v2026.10.08', 'a' * 40,
                                 'b' * 64, 'c' * 64, 'd' * 64, None, False, ())
    value = journal(); value['input_selection'] = release_kit.selection('prebuilt', kit=kit)
    assert prebuilt_install.selected(value) is True
    original = copy.deepcopy(value)
    with pytest.raises(InstallError, match='Prebuilt release-kit upgrades'):
        plan.require_source_build(value)
    assert value == original


@pytest.mark.parametrize('selection', [None, False, [], {}, {'mode': 'source'},
    {'schema': 'iris-install-input-v1', 'mode': 'other'},
    {'schema': 'iris-install-input-v1', 'mode': 'prebuilt', 'kit': {}},
    {'schema': 'iris-install-input-v1', 'mode': 'source', 'kit': {}},
    {'schema': 'iris-install-input-v1', 'mode': 'source', 'offline': False},
    {'schema': True, 'mode': 'source'}])
def test_upgrade_refuses_malformed_source_selection(selection):
    value = journal(); value['input_selection'] = selection
    original = copy.deepcopy(value)
    with pytest.raises(InstallError):
        plan.require_source_build(value)
    assert value == original


@pytest.mark.parametrize('explicit_source', [False, True])
@pytest.mark.parametrize('field', ['release_kit', 'prebuilt_ioxclient', 'prebuilt_kubectl',
                                  'prebuilt_future_authority', 'prebuilt_'])
def test_upgrade_refuses_conflicting_or_unknown_prebuilt_fields(explicit_source, field):
    value = journal()
    if explicit_source:
        value['input_selection'] = release_kit.selection()
    value[field] = None
    original = copy.deepcopy(value)
    with pytest.raises(InstallError):
        plan.require_source_build(value)
    assert value == original


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
