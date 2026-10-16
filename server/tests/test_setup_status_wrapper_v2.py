# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Wrapper receipt versions retain distinct meaning in native/API projections."""

import copy
import hashlib

from openapi_schema_validator import OAS32Validator
import pytest

import openapi_contract
import setup_status


def wrapper(tmp_path, spec, version):
    name, kind, platform, remedy = spec
    path = tmp_path / name
    data = ('synthetic wrapper ' + name).encode()
    path.write_bytes(data)
    values = dict(format='iris-device-wrapper-' + version, wrapper_kind=kind,
                  wrapper_file=name, wrapper_sha256=hashlib.sha256(data).hexdigest(),
                  platform=platform, canonical_index_digest='sha256:' + '1' * 64,
                  canonical_archive_sha256='2' * 64)
    if version == 'v1':
        values['canonical_source_sha256'] = '3' * 64
    else:
        values.update(canonical_neutral_source_sha256='4' * 64,
                      canonical_finalization_sha256='5' * 64)
    return path, values


def readiness(path, values, spec):
    path.with_name(path.name + '.manifest').write_text(
        ''.join(key + '=' + str(value) + '\n' for key, value in values.items()))
    name, kind, platform, remedy = spec
    return setup_status.package_readiness(str(path), name, kind, platform, remedy)


@pytest.fixture(scope='module')
def item_schemas():
    document = openapi_contract.build_document()
    return [document['paths'][prefix + '/settings/setup-status']['get']['responses']['200']
            ['content']['application/json']['schema']['properties']['packages']
            ['properties']['items']['items'] for prefix in ('/api/v1', '/internal/v1')]


@pytest.mark.parametrize('spec', setup_status._PACKAGE_SPECS)
@pytest.mark.parametrize('version', ['v1', 'v2'])
def test_native_wrapper_versions_have_distinct_exact_api_provenance(tmp_path, item_schemas, spec, version):
    path, values = wrapper(tmp_path, spec, version)
    item = readiness(path, values, spec)
    assert item['state'] == 'ok'
    projected = {key: value for key, value in values.items() if key.startswith('canonical_')}
    if version == 'v2':
        projected['format'] = values['format']
        assert 'canonical_source_sha256' not in projected
    assert item['provenance'] == projected
    assert 'native signatures are not inspected' in item['detail']
    assert 'sidecar is not authenticated here' in item['detail']
    for schema in item_schemas:
        OAS32Validator(schema).validate(item)


@pytest.mark.parametrize('version,change', [
    ('v1', {'format': 'unknown'}),
    ('v1', {'canonical_neutral_source_sha256': '4' * 64}),
    ('v1', {'canonical_finalization_sha256': '5' * 64}),
    ('v1', {'unexpected': 'extra'}),
    ('v2', {'canonical_source_sha256': '3' * 64}),
    ('v2', {'format': 'iris-device-wrapper-v1'}),
    ('v2', {'format': 'unknown'}),
    ('v2', {'format': None}),
    ('v2', {'canonical_neutral_source_sha256': None}),
    ('v2', {'canonical_neutral_source_sha256': 'not-a-digest'}),
    ('v2', {'canonical_finalization_sha256': 'A' * 64}),
    ('v2', {'canonical_finalization_sha256': ''}),
    ('v2', {'canonical_finalization_sha256': None}),
    ('v2', {'unexpected': 'extra'}),
])
def test_mixed_unknown_or_incomplete_sidecars_never_become_ready(tmp_path, item_schemas, version, change):
    spec = setup_status._PACKAGE_SPECS[1]
    path, values = wrapper(tmp_path, spec, version)
    for field, value in change.items():
        if value is None:
            values.pop(field)
        else:
            values[field] = value
    item = readiness(path, values, spec)
    assert item['state'] == 'unknown' and item['reason'] == 'provenance-invalid'
    assert item['provenance'] is None
    for schema in item_schemas:
        OAS32Validator(schema).validate(item)


@pytest.mark.parametrize('version', ['v1', 'v2'])
def test_both_receipt_versions_bind_the_actual_wrapper_bytes(tmp_path, version):
    spec = setup_status._PACKAGE_SPECS[2]
    path, values = wrapper(tmp_path, spec, version)
    path.write_bytes(b'changed wrapper after receipt')
    item = readiness(path, values, spec)
    assert item['state'] == 'stale' and item['reason'] == 'wrapper-digest-mismatch'
    assert item['provenance'] is None


@pytest.mark.parametrize('change', [
    {'format': 'unknown'}, {'format': ['iris-device-wrapper-v2']},
    {'format': None}, {'canonical_source_sha256': '3' * 64},
    {'canonical_neutral_source_sha256': ['4' * 64]},
    {'canonical_finalization_sha256': 'not-a-digest'}, {'unexpected': 'extra'},
])
def test_schema_rejects_malformed_v2_projection(tmp_path, item_schemas, change):
    spec = setup_status._PACKAGE_SPECS[0]
    path, values = wrapper(tmp_path, spec, 'v2')
    item = readiness(path, values, spec)
    item['provenance'].update(change)
    for schema in item_schemas:
        assert list(OAS32Validator(schema).iter_errors(item))


def test_schema_requires_explicit_v2_format_and_never_relabels_v1(tmp_path, item_schemas):
    spec = setup_status._PACKAGE_SPECS[0]
    path, values = wrapper(tmp_path, spec, 'v2')
    item = readiness(path, values, spec)
    for field in ('format', 'canonical_neutral_source_sha256', 'canonical_finalization_sha256'):
        changed = copy.deepcopy(item)
        del changed['provenance'][field]
        for schema in item_schemas:
            assert list(OAS32Validator(schema).iter_errors(changed))
    path, values = wrapper(tmp_path, spec, 'v1')
    item = readiness(path, values, spec)
    item['provenance']['format'] = 'iris-device-wrapper-v1'
    for schema in item_schemas:
        assert list(OAS32Validator(schema).iter_errors(item))


@pytest.mark.parametrize('version', ['v1', 'v2'])
def test_schema_rejects_trailing_newline_on_every_provenance_digest(tmp_path, item_schemas, version):
    spec = setup_status._PACKAGE_SPECS[0]
    path, values = wrapper(tmp_path, spec, version)
    item = readiness(path, values, spec)
    for field in item['provenance']:
        if not field.startswith('canonical_'):
            continue
        changed = copy.deepcopy(item)
        changed['provenance'][field] += '\n'
        for schema in item_schemas:
            assert list(OAS32Validator(schema).iter_errors(changed)), field
