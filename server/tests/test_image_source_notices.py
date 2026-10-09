# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Inert ownership and original-notice evidence; no source or image execution."""
import gzip
import hashlib
import io
import json
import lzma
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'tools'))
from iris_installer import image_source_notices as c
from iris_installer.state import InstallError
from test_image_components import inputs, debian, alpine
from test_device_finalize import entry, tar_bytes


def sha(body):
    return hashlib.sha256(body).hexdigest()


def bundle(files, manifest=None):
    if manifest is not None:
        manifest = {**manifest, 'files': {name: {'sha256': sha(body), 'size': len(body)} for name, body in files.items()}}
        files = {**files, c.MANIFEST: c.f._json(manifest)}
    return gzip.compress(tar_bytes([entry(name, body) for name, body in files.items()]), mtime=0)


def record(body):
    return {'type': 'file', '_data': body, 'sha256': sha(body), 'size': len(body), 'mode': 0o644}


def test_metadata_hook_preserves_public_output_and_default(tmp_path):
    path = tmp_path / 'layer.tar'
    path.write_bytes(tar_bytes([entry('var/lib/dpkg/status', debian()), entry('var/lib/dpkg/info/demo.list', b'/usr/bin/demo\n'),
                               entry('usr/bin/demo', b'program', mode=0o755), entry('usr/share/doc/demo/copyright', b'original'),
                               entry('LICENSE', kind=tarfile.LNKTYPE, target='var/lib/dpkg/info/demo.list')]))
    first, second = {}, {}
    assert c.images._layer(path, first) == c.images._layer(path, second, retain_metadata=c._retain)
    assert '_data' not in first['usr/share/doc/demo/copyright']
    assert second['usr/share/doc/demo/copyright']['_data'] == b'original'


def test_metadata_hook_retains_bounds(tmp_path, monkeypatch):
    path = tmp_path / 'layer.tar'
    path.write_bytes(tar_bytes([entry('usr/share/doc/demo/copyright', b'long notice')]))
    monkeypatch.setattr(c.images, 'MAX_FILE_METADATA', 2)
    with pytest.raises(InstallError, match='individual metadata'):
        c.images._layer(path, {}, retain_metadata=c._retain)


def test_dpkg_alias_owners_are_preserved():
    fs = {'var/lib/dpkg/status': record(debian() + debian().replace(b'Package: demo', b'Package: alias')),
          'var/lib/dpkg/info/demo.list': record(b'/usr/bin/demo\n'), 'var/lib/dpkg/info/alias.list': record(b'/usr/bin/alias\n'),
          'usr/bin/demo': record(b'program'), 'usr/bin/alias': {'type': 'symlink', 'target': 'usr/bin/demo'}}
    rows = c._owners(fs, c.Sink())['usr/bin/demo']
    assert {row['package']['package'] for row in rows} == {'demo', 'alias'}
    assert {row['package']['source'] for row in rows} == {'upstream'}


@pytest.mark.parametrize('path', ['/../escape', '//absolute', '/usr/../escape', '/a\\b'])
def test_unsafe_dpkg_paths_refuse(path):
    fs = {'var/lib/dpkg/status': record(debian()), 'var/lib/dpkg/info/demo.list': record((path + '\n').encode())}
    with pytest.raises(InstallError):
        c._owners(fs, c.Sink())


def test_apk_ownership_is_actual_file_metadata():
    rows = c._owners({'lib/apk/db/installed': record(alpine())}, c.Sink())
    assert list(rows) == ['usr/bin/demo'] and rows['usr/bin/demo'][0]['package']['origin'] == 'upstream'


@pytest.mark.parametrize('raw', [alpine().replace(b'F:usr/bin\n', b''), alpine().replace(b'R:demo', b'R:../demo')])
def test_unsafe_apk_paths_refuse(raw):
    with pytest.raises(InstallError):
        c._owners({'lib/apk/db/installed': record(raw)}, c.Sink())


def test_notice_alias_and_missing_original_are_distinct():
    fs = {'notice': {'type': 'symlink', 'target': 'original'}, 'original': record(b'copyright')}
    value = c._notice('notice', fs, c.Sink())
    assert value['resolved_path'] == 'original' and value['sha256'] == sha(b'copyright')
    assert c._notice('missing', fs, c.Sink())['status'] == 'unresolved-original-notice'


def test_notice_cycle_refuses():
    with pytest.raises(InstallError, match='chain'):
        c._notice('a', {'a': {'type': 'symlink', 'target': 'b'}, 'b': {'type': 'symlink', 'target': 'a'}}, c.Sink())


def test_python_script_template_is_compared():
    source = b'#!/usr/bin/env python3\nprint("inert")\n'
    templates = {'version': '3.12.15', 'Tools/scripts/2to3': source}
    body = source.replace(b'/usr/bin/env python3', b'/usr/local/bin/python3.12')
    assert c._script('usr/local/bin/2to3-3.12', body, templates, c.Sink())['kind'] == 'installed-shebang'
    with pytest.raises(InstallError):
        c._script('usr/local/bin/2to3-3.12', body + b'changed', templates, c.Sink())


def test_configured_script_records_substitutions():
    result = c._script('usr/local/bin/python3.12-config', b'prefix="/usr/local"\n',
                       {'version': '3.12.15', 'Misc/python-config.sh.in': b'prefix="@prefix@"\n'}, c.Sink())
    assert result['substitutions'] == [('prefix', '/usr/local')]


def test_policy_source_and_original_notice_are_separate():
    templates = {'policy': b"cat <<-'EOF'\n\t#!/bin/sh\n\texit 101\nEOF\n", 'policy-license': b'original MIT'}
    result = c._script('usr/sbin/policy-rc.d', b'#!/bin/sh\nexit 101\n', templates, c.Sink())
    assert result['notice']['sha256'] == sha(b'original MIT')
    with pytest.raises(InstallError):
        c._script('usr/sbin/policy-rc.d', b'exit 0\n', templates, c.Sink())


@pytest.mark.parametrize('relative', ['server/webroot/console.js', 'server/console-ui/templates/swarmmap.html'])
def test_unbundled_canonical_source_does_not_require_bundle_notices(relative):
    body = b'// original project source, not a third-party bundle\n'
    path = 'opt/iris/' + relative
    summary = {'executables': [], 'unknown_executables': [], 'notice_files': [], 'package_databases': []}
    result = {'executables': [], 'notices': [], 'packages': [], 'web_files': []}
    c._view('console-image', {'platform': 'linux/amd64', 'layers': [{'diff_id': 'sha256:' + '0' * 64}]},
            0, summary, {path: record(body)}, {relative: {'sha256': sha(body)}},
            {}, {}, c.Sink(), result)
    assert result['web_files'][0]['sha256'] == sha(body) and not result['notices']


def test_web_layer_entry_identity_excludes_inherited_but_keeps_reintroduced_bytes(tmp_path):
    path = 'opt/iris/server/webroot/fonts/demo.woff2'
    body = b'exact font data'
    filesystem, result = {}, {'executables': [], 'notices': [], 'packages': [], 'web_files': []}
    view = {'platform': 'linux/amd64', 'layers': [{'diff_id': 'sha256:' + str(i) * 64} for i in range(3)]}
    for index, entries in enumerate([[entry(path, body)], [entry('unrelated', b'x')], [entry(path, body)]]):
        archive = tmp_path / (str(index) + '.tar')
        archive.write_bytes(tar_bytes(entries))
        previous = dict(filesystem)
        changes, _ = c.images._layer(archive, filesystem, retain_metadata=c._retain)
        changed = {name for name, row in filesystem.items() if row is not previous.get(name)}
        c._view('console-image', view, index, changes, filesystem,
                {'server/webroot/fonts/demo.woff2': {'sha256': sha(body)}}, {}, {}, c.Sink(), result, web_paths=changed)
    assert [row['layer'] for row in result['web_files']] == [0, 2]


@pytest.mark.parametrize('fault', ['traversal', 'absolute', 'duplicate', 'tail', 'truncated'])
def test_nested_source_namespace_and_termination(fault):
    entries = [entry('../LICENSE' if fault == 'traversal' else '/LICENSE' if fault == 'absolute' else 'LICENSE', b'original')]
    if fault == 'duplicate':
        entries.append(entry('LICENSE', b'other'))
    plain = tar_bytes(entries)
    plain = plain + b'X' * 512 if fault == 'tail' else plain[:1024] if fault == 'truncated' else plain
    with pytest.raises((InstallError, tarfile.TarError)):
        c._nested_notices(io.BytesIO(gzip.compress(plain)), 'input.tar.gz', c.Sink())


def test_nested_xz_uses_dictionary_memory_limit(monkeypatch):
    monkeypatch.setattr(c.shared, 'MAX_EXPANDED_INDEX', 16 * 1024**2)
    body = lzma.compress(tar_bytes([entry('LICENSE', b'original')]), filters=[{'id': lzma.FILTER_LZMA2, 'dict_size': 32 * 1024**2}])
    with pytest.raises(InstallError):
        c._nested_notices(io.BytesIO(body), 'source.tar.xz', c.Sink())


@pytest.fixture
def pipeline(inputs, tmp_path, monkeypatch):
    inventory = c.images.inspect_components(**inputs)
    digest = sha(inventory.read_bytes())
    directory = tmp_path / 'candidate'
    directory.mkdir()
    files = {}
    for role in ('server', 'console', 'neutral'):
        path = directory / (role + '.tar')
        shutil.copyfile(inputs[role + '_archive'], path)
        files[path.name] = {'sha256': sha(path.read_bytes()), 'size': path.stat().st_size}
    candidate = {'format': 'iris-local-release-candidate-v1', 'authenticated': False, 'commit': inputs['commit'],
                 'version': '2026.10.09', 'tag': 'v2026.10.09', 'profile': 'prepared-host', 'files': files}
    (directory / 'local-candidate.json').write_bytes(c.f._json(candidate))
    monkeypatch.setattr(c.runtime, '_canonical_source', lambda *_: ({}, {}, b'{}'))
    policy, notice = b"cat <<-'EOF'\n\texit 101\nEOF\n", b'original MIT'
    monkeypatch.setattr(c, 'POLICY', {'source': sha(policy), 'license': sha(notice)})
    policy_path, notice_path = tmp_path / 'policy', tmp_path / 'notice'
    policy_path.write_bytes(policy)
    notice_path.write_bytes(notice)
    names = ('Tools/scripts/2to3', 'Tools/scripts/idle3', 'Tools/scripts/pydoc3', 'Misc/python-config.sh.in')
    upstream = lambda version: lzma.compress(tar_bytes([entry('Python-' + version + '/' + name, b'inert') for name in names]))
    source = bundle({'upstream/LICENSE': b'original source notice'})
    source_sha = hashlib.sha512(source).hexdigest()
    source_path = 'sources/sha512/' + source_sha
    records = {
        'debian': ({'readme': b'source references'}, {'sources': [{'name': name, 'version': version, 'files': ['readme']} for name, version in
            [('upstream', '1.0'), ('upstream', '2.0'), ('static-one', '1:2.3'), ('static-two', '4.5'), ('other', '9.0')]]}),
        'alpine': ({'ports/APKBUILD': b'license=MIT', source_path: source}, {'sources': [{'origin': 'upstream', 'version': '2.0-r1',
            'aports_commit': 'b' * 40, 'port_files': {'APKBUILD': {'path': 'ports/APKBUILD'}},
            'inputs': [{'filename': 'upstream.tar.gz', 'path': source_path, 'sha512': source_sha}]}]}),
        'core-python': ({'sources/Python-3.12.15.tar.xz': upstream('3.12.15'), 'sources/pip-25.0.1.tar.gz':
            bundle({'pip-25.0.1/src/pip/_vendor/distlib/scripts.py': b"SCRIPT_TEMPLATE = r'''%(module)s'''"})}, {}),
        'runtime': ({'sources/Python-3.12.14.tar.xz': upstream('3.12.14')}, {})}
    companions = {}
    for role in sorted(c.ROLES):
        path = tmp_path / (role + '.tar.gz')
        raw = bundle({'aria/source': b'inert'}) if role == 'aria2' else bundle(records[role][0],
              {'schema': role, 'scope': role, 'inventory_sha256': digest, **records[role][1]})
        path.write_bytes(raw)
        companions[role] = {'path': path, 'sha256': sha(raw)}
    return {'candidate_dir': directory, 'candidate_sha256': sha(c.f._json(candidate)), 'inventory': inventory,
            'inventory_sha256': digest, 'companions': companions, 'policy_source': policy_path,
            'policy_license': notice_path, 'output_dir': tmp_path / 'output'}


def verify_args(pipeline):
    return {key: value for key, value in pipeline.items() if key not in ('policy_source', 'policy_license', 'output_dir')}


def test_producer_and_independent_validator_never_execute(pipeline, monkeypatch):
    monkeypatch.setattr(subprocess, 'Popen', lambda *_a, **_k: pytest.fail('no program execution'))
    path = c.build_catalog(**pipeline)
    result = c.validate_catalog(path, **verify_args(pipeline))
    assert result['authenticated'] is result['source_coverage_complete'] is result['rebuild_verified'] is False
    assert set(result['companions']) == c.ROLES and len(result['alpine_origins'][0]['notices']) == 1
    assert any(row.get('status') == 'original-bytes-retained' for row in result['notices'])


@pytest.mark.parametrize('fault', ['candidate', 'inventory', 'companion', 'policy', 'license', 'role', 'image'])
def test_changed_external_selections_refuse(pipeline, fault):
    if fault in ('candidate', 'inventory'):
        pipeline[fault + '_sha256'] = '0' * 64
    elif fault == 'companion':
        pipeline['companions']['alpine']['sha256'] = '0' * 64
    elif fault in ('policy', 'license'):
        pipeline['policy_source' if fault == 'policy' else 'policy_license'].write_bytes(b'changed')
    elif fault == 'role':
        del pipeline['companions']['aria2']
    else:
        (pipeline['candidate_dir'] / 'server.tar').write_bytes(b'changed')
    with pytest.raises(InstallError):
        c.build_catalog(**pipeline)
    assert not pipeline['output_dir'].exists()


@pytest.mark.parametrize('fault', ['manifest', 'notice', 'extra'])
def test_catalog_claims_and_bytes_are_reconstructed(pipeline, fault):
    path = c.build_catalog(**pipeline)
    with tarfile.open(path) as archive:
        files = {row.name: archive.extractfile(row).read() for row in archive}
    if fault == 'manifest':
        value = json.loads(files[c.MANIFEST])
        value['source_coverage_complete'] = True
        files[c.MANIFEST] = c.f._json(value)
    elif fault == 'notice':
        files[next(name for name in files if name.startswith('data/'))] = b'changed'
    else:
        files['extra'] = b'unlisted'
    changed = path.parent.parent / 'changed.tar.gz'
    changed.write_bytes(bundle(files))
    with pytest.raises(InstallError):
        c.validate_catalog(changed, **verify_args(pipeline))


def test_existing_output_is_preserved(pipeline):
    output = pipeline['output_dir']
    output.mkdir()
    (output / 'sentinel').write_bytes(b'owner')
    with pytest.raises(InstallError, match='already exists'):
        c.build_catalog(**pipeline)
    assert (output / 'sentinel').read_bytes() == b'owner'


def test_output_parent_replacement_does_not_redirect_publication_or_cleanup(pipeline, monkeypatch):
    original = c._assemble
    parent = pipeline['output_dir'].parent
    moved = parent.with_name(parent.name + '-held')
    def replace(*args, **kwargs):
        result = original(*args, **kwargs)
        parent.rename(moved)
        parent.mkdir(mode=0o700)
        (parent / 'sentinel').write_bytes(b'owner')
        return result
    monkeypatch.setattr(c, '_assemble', replace)
    try:
        with pytest.raises((InstallError, OSError)):
            c.build_catalog(**pipeline)
        assert (parent / 'sentinel').read_bytes() == b'owner'
        assert set(parent.iterdir()) == {parent / 'sentinel'}
        assert not (moved / 'output').exists()
        assert not list(moved.glob('.iris-packaging-*'))
    finally:
        shutil.rmtree(parent)
        moved.rename(parent)


def test_companion_mutation_after_assembly_prevents_publication(pipeline, monkeypatch):
    original = c._assemble
    called = False
    def mutate(*args, **kwargs):
        nonlocal called
        result = original(*args, **kwargs)
        if not called:
            called = True
            pipeline['companions']['alpine']['path'].write_bytes(b'changed')
        return result
    monkeypatch.setattr(c, '_assemble', mutate)
    with pytest.raises(InstallError, match='digest'):
        c.build_catalog(**pipeline)
    assert not pipeline['output_dir'].exists()


def test_bad_zip_has_concise_cli_failure(pipeline, monkeypatch, capsys):
    def malformed(*args, **kwargs):
        c._nested_notices(io.BytesIO(b'bad zip'), 'input.zip', c.Sink())
    monkeypatch.setattr(c, 'build_catalog', malformed)
    args = []
    for key, value in pipeline.items():
        if key == 'companions':
            for role, row in value.items():
                args.extend(['--' + role, str(row['path']), '--' + role + '-sha256', row['sha256']])
        else:
            args.extend(['--' + key.replace('_', '-'), str(value)])
    with pytest.raises(SystemExit) as stopped:
        c.main(args)
    assert stopped.value.code == 1 and 'Traceback' not in capsys.readouterr().err
