# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Local runtime-source bindings, closed archives and publication custody."""

import gzip
import hashlib
import io
import json
import lzma
import os
from pathlib import Path
import subprocess
import sys
import tarfile

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'tools'))
from iris_installer import runtime_sources as r
from iris_installer.state import InstallError


def digest(data):
    return hashlib.sha256(data).hexdigest()


def packed(files, *, links=(), compression=None):
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode='w:', format=tarfile.PAX_FORMAT) as tar:
        for name, data in files.items():
            member = tarfile.TarInfo(name)
            member.mode, member.size = 0o644, len(data)
            tar.addfile(member, io.BytesIO(data))
        for name, target, symbolic in links:
            member = tarfile.TarInfo(name)
            member.type = tarfile.SYMTYPE if symbolic else tarfile.LNKTYPE
            member.linkname = target
            tar.addfile(member)
    data = stream.getvalue()
    return gzip.compress(data, mtime=0) if compression == 'gz' else lzma.compress(data) if compression == 'xz' else data


def row(name, data, component=None):
    value = {'path': name, 'type': 'file', 'mode': 0o644, 'size': len(data), 'sha256': digest(data)}
    if component:
        value['observed_component_path'] = component
    return value


def layer(files, member, *, links=()):
    plain = packed(files, links=links)
    data = gzip.compress(plain, mtime=0)
    copied, notices = [], []
    for name, content in files.items():
        component = r.images._component(name)
        if component:
            copied.append(row(name, content, component))
        if r.images._notice(name):
            notices.append(row(name, content))
    return data, {'index': 0, 'member': member, 'blob_sha256': digest(data), 'blob_size': len(data),
        'diff_id': 'sha256:' + digest(plain), 'expanded_size': len(plain),
        'inventory': {'copied_component_files': copied, 'notice_files': notices}}


@pytest.fixture
def inputs(tmp_path, monkeypatch):
    candidate, pool = tmp_path / 'candidate', tmp_path / 'pool'
    candidate.mkdir(); pool.mkdir()
    controls = {name: ('reviewed fixture control ' + name + '\n').encode() for name in r.CONTROLS}
    monkeypatch.setattr(r, 'CONTROLS', {name: digest(data) for name, data in controls.items()})
    sources = {
        'Python-3.12.14.tar.xz': packed({'Python-3.12.14/Include/patchlevel.h': b'#define PY_VERSION "3.12.14"\n',
            'Python-3.12.14/Lib/demo.py': b'NEVER_EXECUTE = True\n',
            'Python-3.12.14/LICENSE': b'Python original license\n',
            'Python-3.12.14/Modules/expat/COPYING': b'Expat original license\n'}, compression='xz'),
        'cpython-expat-backport.patch': ('From ' + r.PATCH_COMMIT + ' fixture\n').encode(),
        'openssh-10.5p1.tar.gz': packed({'openssh-10.5p1/LICENCE': b'OpenSSH original license\n',
                                      'openssh-10.5p1/configure': b'NEVER EXECUTE\n'}, compression='gz'),
    }
    monkeypatch.setattr(r, 'SOURCES', {name: digest(data) for name, data in sources.items()})
    for name, data in sources.items():
        (pool / name).write_bytes(data)
    alpine = tmp_path / 'alpine.tar.gz'
    alpine.write_bytes(b'validated Alpine fixture')
    openssl = b'OpenSSL original license\n'
    def validated_alpine(path, expected, inventory, inventory_digest):
        assert r._read(path, expected) == b'validated Alpine fixture'
        return {'archive_sha256': expected, 'schema': r.alpine.SCHEMA,
                'sources': {name: {'version': pair[0], 'aports_commit': pair[1]} for name, pair in r.ALPINE.items()},
                'delivery': 'same-exact-companion-required-alongside'}, openssl, controls['tools/licenses/musl-COPYRIGHT']
    monkeypatch.setattr(r, '_alpine', validated_alpine)
    canonical = {**controls, 'VERSION': b'2026.10.08\n', 'device/agent/demo.py': b'NEVER EXECUTE\n',
        'device/verify_image.py': b'VERIFY = True\n', 'device/agent/peer-transfer-hook.sh': b'NEVER EXECUTE\n',
        'device/container/entrypoint.sh': b'NEVER EXECUTE\n', 'device/container/reconcile.sh': b'NEVER EXECUTE\n',
        'deliverables/aria2c-x86_64': b'aria amd64', 'deliverables/aria2c-aarch64': b'aria arm64'}
    records = {name: {**r.shared._record(data), 'mode': 0o644} for name, data in canonical.items()}
    context = r._context(canonical, records)
    commit = '1' * 40
    source_inventory = {'schema': 1, 'commit': commit, 'files': {name: digest(data) for name, data in canonical.items()}}
    (candidate / 'fixture.deb.source.json').write_bytes(r.f._json(source_inventory))
    (candidate / 'iris.tgz').write_bytes(packed({'iris/' + name: data for name, data in canonical.items()}, compression='gz'))
    suffix = b'\n\nStatically linked musl libc 1.2.6:\n\n' + controls['tools/licenses/musl-COPYRIGHT']
    aead, ssh = openssl + suffix, b'OpenSSH original license\n' + suffix
    outer, views = {}, []
    for arch, triple in (('amd64', 'x86_64'), ('arm64', 'aarch64')):
        files = {'usr/local/include/python3.12/pyconfig.h': b'generated config ' + arch.encode(),
            'usr/local/lib/python3.12/_sysconfigdata__linux_' + triple + '-linux-musl.py': b'NEVER EXECUTE CONFIG\n',
            'usr/local/bin/python3.12': b'python binary ' + arch.encode(),
            'usr/local/include/python3.12/patchlevel.h': b'#define PY_VERSION "3.12.14"\n',
            'usr/local/lib/python3.12/demo.py': b'NEVER_EXECUTE = True\n',
            'usr/local/lib/python3.12/__pycache__/demo.pyc': b'generated pyc',
            'opt/iris/bin/iris-aead': b'aead binary ' + arch.encode(),
            'usr/local/share/licenses/iris-aead.LICENCE': aead,
            'usr/local/share/licenses/iris-python/PYTHON-LICENSE': b'Python original license\n',
            'usr/local/share/licenses/iris-python/EXPAT-COPYING': b'Expat original license\n'}
        for name in ('Makefile', 'Setup', 'Setup.local', 'Setup.bootstrap', 'Setup.stdlib', 'config.c', 'python-config.py'):
            files['usr/local/lib/python3.12/config-3.12-' + triple + '-linux-musl/' + name] = b'inert build config'
        data, record = layer(files, arch + '.layer', links=(('usr/local/bin/python3', 'python3.12', True),))
        config = r.f._json({'architecture': arch, 'rootfs': {'diff_ids': [record['diff_id']]}})
        config_digest = 'sha256:' + digest(config)
        outer[arch + '.layer'] = data
        outer['blobs/sha256/' + digest(config)] = config
        views.append({'platform': 'linux/' + arch, 'config_digest': config_digest,
                      'manifest_digest': 'sha256:' + arch[0] * 64, 'layers': [record]})
    (candidate / 'iris-device-neutral.oci.tar').write_bytes(packed(outer))
    files = {'opt/iris/bin/iris-aead': b'aead amd64', 'opt/iris/bin/iris-aead-amd64': b'aead amd64',
             'opt/iris/bin/ssh-keygen-amd64': b'static openssh amd64',
             'opt/iris/bin/iris-aead.LICENCE': aead, 'opt/iris/bin/ssh-keygen.LICENCE': ssh}
    data, record = layer(files, 'server.layer')
    config = r.f._json({'architecture': 'amd64', 'rootfs': {'diff_ids': [record['diff_id']]}})
    server = packed({'manifest.json': r.f._json([{'Config': 'config.json', 'Layers': ['server.layer']}]),
                     'config.json': config, 'server.layer': data})
    (candidate / 'iris-server-amd64.docker.tar').write_bytes(server)
    (candidate / 'iris-console-amd64.docker.tar').write_bytes(b'other inventory-selected image')
    images = {'server-image': {'platform': 'linux/amd64', 'config_digest': 'sha256:' + digest(config), 'layers': [record]},
              'console-image': {}, 'device-runtime': {'platforms': views, 'index_digest': 'sha256:' + '9' * 64}}
    for role, name in (('server-image', 'iris-server-amd64.docker.tar'), ('console-image', 'iris-console-amd64.docker.tar'),
                       ('device-runtime', 'iris-device-neutral.oci.tar')):
        raw = (candidate / name).read_bytes()
        images[role].update(archive_sha256=digest(raw), archive_size=len(raw))
    neutral = {'format': 'iris-device-neutral-oci-v1', 'trust_mode': 'neutral', 'source_sha256': context['source_sha256'],
        'index_digest': images['device-runtime']['index_digest'], 'archive_sha256': images['device-runtime']['archive_sha256'],
        'platforms': 'linux/amd64,linux/arm64'}
    (candidate / 'iris-device-neutral.oci.tar.manifest').write_text(''.join(k + '=' + v + '\n' for k, v in neutral.items()))
    selection = {'format': 'iris-local-release-candidate-v1', 'authenticated': False, 'commit': commit,
        'version': '2026.10.08', 'tag': 'v2026.10.08', 'profile': 'prepared-host', 'source_match': {'canonical_source_matches': False},
        'files': {p.name: r.shared._record(p.read_bytes()) for p in candidate.iterdir()}}
    (candidate / 'local-candidate.json').write_bytes(r.f._json(selection))
    inventory = tmp_path / 'inventory.json'
    value = {'format': 'iris-image-component-inventory-v1', 'scope': 'inventory-only', 'authenticated': False,
             'source_coverage_complete': False, 'commit': commit, 'images': images}
    inventory.write_bytes(r.f._json(value))
    return {'candidate_dir': candidate, 'candidate_sha256': digest(r.f._json(selection)), 'inventory': inventory,
        'inventory_sha256': digest(inventory.read_bytes()), 'source_pool': pool, 'alpine_sources': alpine,
        'alpine_sources_sha256': digest(alpine.read_bytes()), 'output_dir': tmp_path / 'output',
        'selection': selection, 'value': value, 'canonical': canonical}


def arguments(inputs):
    return {name: value for name, value in inputs.items() if name not in ('selection', 'value', 'canonical')}


def build(inputs, **changes):
    return r.build_sources(**(arguments(inputs) | changes))


def validate(inputs, archive):
    args = arguments(inputs)
    args.pop('source_pool'); args.pop('output_dir')
    return r.validate_source_archive(archive, **args)


def rewrite_candidate(inputs, name, data):
    (inputs['candidate_dir'] / name).write_bytes(data)
    inputs['selection']['files'][name] = r.shared._record(data)
    raw = r.f._json(inputs['selection'])
    (inputs['candidate_dir'] / 'local-candidate.json').write_bytes(raw)
    inputs['candidate_sha256'] = digest(raw)


def rewrite_inventory(inputs):
    raw = r.f._json(inputs['value'])
    inputs['inventory'].write_bytes(raw)
    inputs['inventory_sha256'] = digest(raw)


def entries(path):
    with tarfile.open(path, 'r:gz') as tar:
        return {m.name: tar.extractfile(m).read() for m in tar}


def test_round_trip_exact_inputs_notices_configuration_and_truthful_scope(inputs):
    result = build(inputs)
    manifest = validate(inputs, Path(result['archive']))
    assert manifest['schema'] == r.SCHEMA
    assert not manifest['authenticated'] and not manifest['rebuild_verified'] and not manifest['source_coverage_complete']
    assert len(manifest['context']['inputs']) == 15
    assert sum(row['classification'] == 'generated-empty-neutral-input' for row in manifest['context']['inputs'].values()) == 2
    assert manifest['context']['hash_includes_modes'] is False
    assert manifest['alpine_reference']['archive_sha256'] == inputs['alpine_sources_sha256']
    assert manifest['component_inputs']['static-openssh']['alpine_sources'] == ['musl']
    classifications = {row['classification'] for row in manifest['observed_files']}
    assert {'upstream-source-data-exact', 'observed-generated-binary-not-reproduced',
            'observed-generated-build-configuration', 'observed-generated-bytecode-not-reproduced'} <= classifications
    assert sum(row['binding'] == 'source-notice-composition-exact' for row in manifest['notices']) == 8
    payload = entries(Path(result['archive']))
    assert payload['sources/cpython-expat-backport.patch'].startswith(b'From ')
    assert (inputs['output_dir'].stat().st_mode & 0o777) == 0o700
    assert (Path(result['archive']).stat().st_mode & 0o777) == 0o444
    # The deliberately false source_match flag was never promoted into authority.
    assert inputs['selection']['source_match']['canonical_source_matches'] is False


def test_deterministic_repeat(inputs):
    first = build(inputs)
    second = build(inputs, output_dir=inputs['output_dir'].with_name('second'))
    assert first['sha256'] == second['sha256']


@pytest.mark.parametrize('field', ['candidate_sha256', 'inventory_sha256', 'alpine_sources_sha256'])
def test_external_pins_are_authority(inputs, field):
    with pytest.raises(InstallError):
        build(inputs, **{field: '9' * 64})
    assert not inputs['output_dir'].exists()


@pytest.mark.parametrize('name', list(r.SOURCES))
@pytest.mark.parametrize('mutation', ['changed', 'missing', 'symlink', 'hardlink'])
def test_upstream_source_custody(inputs, name, mutation, tmp_path):
    path = inputs['source_pool'] / name
    if mutation == 'changed': path.write_bytes(b'wrong source')
    elif mutation == 'missing': path.unlink()
    elif mutation == 'symlink':
        path.rename(tmp_path / 'target'); path.symlink_to(tmp_path / 'target')
    else: os.link(path, tmp_path / 'alias')
    with pytest.raises((InstallError, OSError)):
        build(inputs)
    assert not inputs['output_dir'].exists()


def test_canonical_source_edit_fails_even_with_new_outer_candidate_pin(inputs):
    canonical = dict(inputs['canonical']); canonical['device/agent/demo.py'] = b'dirty source'
    rewrite_candidate(inputs, 'iris.tgz', packed({'iris/' + k: v for k, v in canonical.items()}, compression='gz'))
    with pytest.raises(InstallError, match='differs from installer'):
        build(inputs)


def test_unknown_recipe_fails_even_with_consistent_source_inventory(inputs):
    canonical = dict(inputs['canonical']); canonical['server/Dockerfile'] = b'new unsupported recipe'
    sidecar = {'schema': 1, 'commit': inputs['selection']['commit'], 'files': {k: digest(v) for k, v in canonical.items()}}
    rewrite_candidate(inputs, 'fixture.deb.source.json', r.f._json(sidecar))
    rewrite_candidate(inputs, 'iris.tgz', packed({'iris/' + k: v for k, v in canonical.items()}, compression='gz'))
    with pytest.raises(InstallError, match='unknown build recipe'):
        build(inputs)


@pytest.mark.parametrize('mutation', ['context', 'trust', 'duplicate', 'archive', 'platform'])
def test_neutral_binding_is_exact(inputs, mutation):
    name = 'iris-device-neutral.oci.tar.manifest'
    raw = (inputs['candidate_dir'] / name).read_bytes()
    if mutation == 'duplicate': raw += b'format=iris-device-neutral-oci-v1\n'
    elif mutation == 'context': raw = re_sub(raw, b'source_sha256=', b'0' * 64)
    elif mutation == 'trust': raw = raw.replace(b'trust_mode=neutral', b'trust_mode=deployment')
    elif mutation == 'archive': raw = re_sub(raw, b'archive_sha256=', b'0' * 64)
    else: raw = raw.replace(b'linux/amd64,linux/arm64', b'linux/amd64')
    rewrite_candidate(inputs, name, raw)
    with pytest.raises(InstallError): build(inputs)


def re_sub(data, prefix, value):
    return b'\n'.join(prefix + value if line.startswith(prefix) else line for line in data.split(b'\n'))


@pytest.mark.parametrize('mutation', ['commit', 'image', 'source-data', 'missing-helper', 'missing-config', 'missing-notice'])
def test_inventory_disagreement_never_becomes_a_coverage_claim(inputs, mutation):
    value = inputs['value']
    view = value['images']['device-runtime']['platforms'][0]
    copied = view['layers'][0]['inventory']['copied_component_files']
    if mutation == 'commit': value['commit'] = '2' * 40
    elif mutation == 'image': value['images']['device-runtime']['archive_sha256'] = '2' * 64
    elif mutation == 'source-data':
        next(row for row in copied if row['path'].endswith('/demo.py'))['sha256'] = '2' * 64
    elif mutation == 'missing-helper': copied[:] = [row for row in copied if row['observed_component_path'] != 'iris-aead']
    elif mutation == 'missing-config': copied[:] = [row for row in copied if not row['path'].endswith('/pyconfig.h')]
    else: view['layers'][0]['inventory']['notice_files'] = []
    rewrite_inventory(inputs)
    with pytest.raises(InstallError): build(inputs)


@pytest.mark.parametrize('mutation', ['manifest-claim', 'manifest-bool-type', 'manifest-number-type',
                                     'source-and-manifest', 'control', 'extra', 'missing'])
def test_independent_validator_reconstructs_not_self_manifest(inputs, mutation, tmp_path):
    result = build(inputs); values = entries(Path(result['archive']))
    manifest = json.loads(values[r.MANIFEST])
    if mutation == 'manifest-claim': manifest['rebuild_verified'] = True
    elif mutation == 'manifest-bool-type': manifest['rebuild_verified'] = 0
    elif mutation == 'manifest-number-type':
        record = next(iter(manifest['files'].values())); record['size'] = float(record['size'])
    elif mutation == 'source-and-manifest':
        name = 'sources/cpython-expat-backport.patch'; values[name] += b'changed'
        manifest['files'][name] = r._record(values[name])
    elif mutation == 'control': values['controls/server/Dockerfile'] += b'changed'
    elif mutation == 'extra': values['unlisted'] = b'no'
    else: del values['README.txt']
    values[r.MANIFEST] = r.f._json(manifest)
    path = tmp_path / 'altered.tar.gz'; path.write_bytes(packed(values, compression='gz'))
    with pytest.raises(InstallError): validate(inputs, path)


@pytest.mark.parametrize('symbolic', [False, True])
def test_layer_parser_supports_safe_links_but_source_parser_refuses(symbolic):
    data = packed({'target': b'content'}, links=(('alias', 'target', symbolic),))
    with r._tar(io.BytesIO(data), links=True) as (_, members):
        assert members['alias'].linkname == 'target'
    with pytest.raises(InstallError):
        with r._tar(io.BytesIO(data)):
            pass


@pytest.mark.parametrize('target', ['../../escape', '/../../escape', 'bad\\target'])
def test_layer_link_escape_refused(target):
    data = packed({}, links=(('alias', target, True),))
    with pytest.raises(InstallError):
        with r._tar(io.BytesIO(data), links=True): pass


@pytest.mark.parametrize('mutation', ['no-end', 'trailing', 'traversal', 'duplicate', 'owner-name', 'mode'])
def test_tar_closed_shape_and_companion_metadata(mutation):
    data = packed({'safe': b'content'})
    if mutation == 'no-end': data = data[:1024]
    elif mutation == 'trailing': data += b'foreign'
    elif mutation == 'traversal': data = packed({'../escape': b'content'})
    elif mutation == 'duplicate': data = data[:1024] + data
    else:
        stream = io.BytesIO()
        with tarfile.open(fileobj=stream, mode='w:') as tar:
            member = tarfile.TarInfo('safe'); member.size = 1
            if mutation == 'owner-name': member.uname = 'not canonical'
            else: member.mode = 0o755
            tar.addfile(member, io.BytesIO(b'x'))
        data = stream.getvalue()
    with pytest.raises(InstallError):
        with r._tar(io.BytesIO(data), strict=True): pass


def test_existing_output_never_replaced(inputs):
    inputs['output_dir'].mkdir(); sentinel = inputs['output_dir'] / 'owner'
    sentinel.write_bytes(b'preserve')
    with pytest.raises(InstallError): build(inputs)
    assert sentinel.read_bytes() == b'preserve'


def test_output_parent_replacement_does_not_redirect_cleanup(inputs, monkeypatch, tmp_path):
    parent = tmp_path / 'publication'; parent.mkdir(mode=0o700)
    original = tmp_path / 'original-publication'
    real = r._validate
    def substituted(*args, **kwargs):
        result = real(*args, **kwargs)
        stage = next(parent.iterdir()).name
        parent.rename(original); parent.mkdir(); (parent / stage).mkdir()
        (parent / stage / 'owner').write_bytes(b'preserve')
        return result
    monkeypatch.setattr(r, '_validate', substituted)
    with pytest.raises(InstallError) as raised: build(inputs, output_dir=parent / 'out')
    assert 'parent changed' in str(raised.value)
    assert next(parent.iterdir()).joinpath('owner').read_bytes() == b'preserve'
    assert list(original.iterdir()) == []


def test_no_source_or_configuration_execution(inputs, monkeypatch):
    def forbidden(*args, **kwargs): pytest.fail('execution is outside source collection')
    monkeypatch.setattr(subprocess, 'run', forbidden)
    monkeypatch.setattr(subprocess, 'Popen', forbidden)
    build(inputs)


def test_cli_build_verify_and_argument_rules(inputs, capsys):
    args = []
    for name, value in arguments(inputs).items():
        args += ['--' + name.replace('_', '-'), str(value)]
    assert r.main(args) == 0
    assert json.loads(capsys.readouterr().out)['rebuild_verified'] is False
    verify = []
    for name, value in arguments(inputs).items():
        if name not in ('source_pool', 'output_dir'):
            verify += ['--' + name.replace('_', '-'), str(value)]
    verify += ['--verify-bundle', str(inputs['output_dir'] / r.BUNDLE)]
    assert r.main(verify) == 0
    with pytest.raises(SystemExit) as raised:
        r.main(verify + ['--source-pool', str(inputs['source_pool'])])
    assert raised.value.code == 2


def test_cli_invalid_input_is_sanitized(tmp_path, capsys):
    args = ['--candidate-dir', str(tmp_path), '--candidate-sha256', '0' * 64,
        '--inventory', str(tmp_path / 'absent'), '--inventory-sha256', '0' * 64,
        '--alpine-sources', str(tmp_path / 'absent'), '--alpine-sources-sha256', '0' * 64,
        '--source-pool', str(tmp_path), '--output-dir', str(tmp_path / 'out')]
    with pytest.raises(SystemExit) as raised: r.main(args)
    assert raised.value.code == 1
    assert str(tmp_path) not in capsys.readouterr().err


@pytest.mark.parametrize('headers', [{'comment': '1' * 40}, {'path': 'substitute'}, {'comment': 'not a Git object'},
                                     {'comment': '1' * 40, 'size': '999999999'}, {'comment': '1' * 300}])
def test_only_fixed_musl_source_reader_accepts_bounded_inert_global_comment(headers):
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode='w:', format=tarfile.PAX_FORMAT, pax_headers=headers) as archive:
        member = tarfile.TarInfo('musl-1.2.6/COPYRIGHT'); member.size = 7
        archive.addfile(member, io.BytesIO(b'license'))
    raw = gzip.compress(stream.getvalue(), mtime=0)
    with pytest.raises(InstallError): r._upstream(raw, 'musl-1.2.6', 'gz')
    if headers == {'comment': '1' * 40}:
        _, notices = r._upstream(raw, 'musl-1.2.6', 'gz', git_comment=True)
        assert notices['COPYRIGHT'] == b'license'
    else:
        with pytest.raises((InstallError, tarfile.TarError)):
            r._upstream(raw, 'musl-1.2.6', 'gz', git_comment=True)


def test_canonical_musl_notice_must_equal_pinned_upstream_notice(inputs, monkeypatch):
    original = r._alpine
    def changed(*args):
        reference, openssl, _ = original(*args)
        return reference, openssl, b'other musl notice'
    monkeypatch.setattr(r, '_alpine', changed)
    with pytest.raises(InstallError, match='musl notice differs'):
        build(inputs)


def test_source_expansion_and_payload_bounds(inputs, monkeypatch):
    monkeypatch.setattr(r, 'MAX_TOTAL', 1)
    with pytest.raises(InstallError, match='aggregate bound'):
        build(inputs)
    raw = packed({'safe': b'x' * 4096}, compression='gz')
    with pytest.raises(InstallError):
        with r._tar(io.BytesIO(raw), compression='gz', maximum=512): pass


@pytest.mark.parametrize('name,source', [('LICENSE.txt', 'LICENSE'),
    ('config-3.12-x86_64-linux-musl/config.c.in', 'Modules/config.c.in'),
    ('config-3.12-aarch64-linux-musl/install-sh', 'install-sh'),
    ('config-3.12-x86_64-linux-musl/makesetup', 'Modules/makesetup')])
def test_installed_python_source_remaps_require_exact_bytes(name, source):
    path = 'usr/local/lib/python3.12/' + name
    observed = row(path, b'exact source', 'cpython-runtime')
    view = {'platform': 'linux/amd64', 'layers': [{'index': 0, 'diff_id': 'sha256:' + '1' * 64,
        'inventory': {'copied_component_files': [observed]}}]}
    mapped, _ = r._observed(view, 'device-runtime', {source: r.shared._record(b'exact source')})
    assert mapped[0]['source'] == source and mapped[0]['classification'] == 'upstream-source-data-exact'
    with pytest.raises(InstallError): r._observed(view, 'device-runtime', {source: r.shared._record(b'different')})


@pytest.mark.parametrize('name,classification', [
    ('config-3.12-x86_64-linux-musl/python.o', 'observed-generated-binary-not-reproduced'),
    ('lib2to3/Grammar3.12.14.final.0.pickle', 'observed-generated-grammar-data-not-reproduced'),
    ('lib2to3/PatternGrammar3.12.14.final.0.pickle', 'observed-generated-grammar-data-not-reproduced'),
    ('unknown.data', 'unmapped-runtime-file-not-source-equal')])
def test_generated_and_unknown_python_paths_do_not_claim_source_equality(name, classification):
    observed = row('usr/local/lib/python3.12/' + name, b'generated', 'cpython-runtime')
    view = {'platform': 'linux/amd64', 'layers': [{'index': 0, 'diff_id': 'sha256:' + '1' * 64,
        'inventory': {'copied_component_files': [observed]}}]}
    mapped, _ = r._observed(view, 'device-runtime', {})
    assert mapped[0]['classification'] == classification and mapped[0]['source'] is None
