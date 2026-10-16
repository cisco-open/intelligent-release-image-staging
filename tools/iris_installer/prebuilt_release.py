# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Check exact prebuilt evidence and an attributed review before unsigned sealing.

The caller supplies the review statement and its independent digest. This helper
checks byte/selection bindings; it cannot authenticate the reviewer or confer
legal, owner, publication, or reproducible-build approval.
"""

import argparse
from contextlib import contextmanager
from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import re
import secrets
import tarfile
import zlib

from . import candidate_evidence as completion, offline_inputs as custody, release_kit as kit
from . import runtime_sources as runtime
from .device_finalize import _json as canonical
from .packaging_inputs import _publication
from .state import InstallError, regular_bytes


REVIEW_SCHEMA = 'iris-prebuilt-source-review-v1'
PREPARATION_SCHEMA = 'iris-prebuilt-preparation-v1'
REVIEW_NAME = 'source-review.json'
PREPARATION_NAME = 'prebuilt-preparation.json'
STAGE_NAME = 'release-stage.json'
REVIEW_FIELDS = {'format', 'scope', 'decision', 'tag', 'commit', 'candidate_evidence_sha256',
                'payload_assets', 'payload_asset_map_sha256', 'image_inventory_sha256', 'companions',
                'reviewer', 'reference', 'statement'}
EVIDENCE_FIELDS = {'format', 'authenticated', 'source_coverage_complete', 'rebuild_verified',
                   'original_candidate_sha256', 'tag', 'commit', 'profile', 'image_inventory_sha256',
                   'source_agreement', 'neutral_source_sha256', 'external_pins', 'companions', 'files',
                   'mechanical_evidence', 'remaining_gates'}
RESERVED = {REVIEW_NAME, PREPARATION_NAME, 'release.json', 'SHA256SUMS', 'attestations.jsonl', 'release-stage.json'}


def fail(message):
    raise InstallError('Prebuilt preparation: ' + message)


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _asset_map(records):
    if not isinstance(records, dict) or not 1 <= len(records) <= kit.MAX_ASSETS:
        fail('asset inventory exceeds supported bounds')
    total = 0
    for name, row in records.items():
        kit._name(name)
        kit._keys(row, {'sha256', 'size'})
        kit._sha(row['sha256'])
        if type(row['size']) is not int or not 0 < row['size'] <= kit.MAX_ASSET:
            fail('asset inventory has an invalid size')
        total += row['size']
    if total > kit.MAX_TOTAL:
        fail('asset inventory exceeds total size limit')


def _snapshot_completed(source, expected, destination, anchor, tag, commit):
    source = kit._path(source)
    directory = kit._protected_directory(source)
    try:
        anchor.mkdir(mode=0o700)
        if kit._snapshot(source / completion.MANIFEST, anchor / completion.MANIFEST, kit.MAX_METADATA) != expected:
            fail('completed candidate differs from its external digest')
        value = kit._json(regular_bytes(anchor / completion.MANIFEST, kit.MAX_METADATA))
        kit._keys(value, EVIDENCE_FIELDS)
        if (value['format'] != completion.SCHEMA or (value['tag'], value['commit']) != (tag, commit)
                or any(value[key] is not False for key in ('authenticated', 'source_coverage_complete', 'rebuild_verified'))
                or not isinstance(value['profile'], str) or value['profile'] not in kit.PROFILES):
            fail('completed candidate identity or scope is unsupported')
        records = value['files']
        _asset_map(records)
        if set(records) & (RESERVED | {completion.MANIFEST}) or completion.ORIGINAL not in records:
            fail('completed candidate contains reserved metadata or omits the original seal')
        names = {*records, completion.MANIFEST}
        if set(os.listdir(directory)) != names:
            fail('completed candidate is not a closed file set')
        for name, row in sorted(records.items()):
            if (kit._snapshot(source / name, anchor / name, kit.MAX_ASSET) != row['sha256']
                    or (anchor / name).stat().st_size != row['size']):
                fail('completed candidate asset differs from its inventory')
        custody._same_directory(source, directory)
        if set(os.listdir(directory)) != names:
            fail('completed candidate changed during snapshot')
    finally:
        os.close(directory)
    all_assets = {**records, completion.MANIFEST: {'sha256': expected,
                 'size': (anchor / completion.MANIFEST).stat().st_size}}
    _asset_map(all_assets)
    return value, all_assets


def _git_selection(repository, tag, commit):
    repository = kit._path(repository)
    builder = completion._helper('build-release-candidate.py')
    environment = {'PATH': '/usr/bin:/bin', 'LC_ALL': 'C', 'GIT_CONFIG_NOSYSTEM': '1',
                   'GIT_CONFIG_GLOBAL': '/dev/null', 'GIT_NO_REPLACE_OBJECTS': '1',
                   'GIT_NO_LAZY_FETCH': '1', 'GIT_ALLOW_PROTOCOL': '', 'GIT_TERMINAL_PROMPT': '0'}
    def read(arguments):
        return builder._git(repository, arguments, environment)
    if (read(['rev-parse', '--verify', 'HEAD']).strip().decode('ascii') != commit
            or read(['rev-parse', '--verify', 'refs/tags/' + tag + '^{commit}']).strip().decode('ascii') != commit
            or regular_bytes(repository / 'VERSION', 128) != (tag[1:] + '\n').encode('ascii')):
        fail('repository HEAD, exact tag, clean tracked source, and VERSION must agree')
    tree = builder._tree(repository, commit, environment)
    # Raw byte/mode comparison avoids git status invoking repository-configured
    # fsmonitor/clean filters. No checkout, recipe, hook or transport is run.
    builder._verify_checkout(repository, tree)
    return tree


def _git_source_parity(original, candidate, tree):
    """Compare every shipped canonical source byte/mode with local Git blobs.

    Local Git is independently selected by the caller, not supplied by the kit.
    This is exact source parity, not evidence that image binaries were rebuilt.
    """
    sidecars = [name for name in candidate['files'] if name.endswith('.deb.source.json')]
    if len(sidecars) != 1:
        fail('exactly one retained installer source inventory is required')
    sidecar = kit._json(regular_bytes(original / sidecars[0], kit.MAX_METADATA))
    kit._keys(sidecar, {'schema', 'commit', 'files'})
    selector = completion._helper('build-installer-package.py').selected
    selected = {name for name in tree if selector(name)}
    if (type(sidecar['schema']) is not int or sidecar['schema'] != 1 or sidecar['commit'] != candidate['commit']
            or not isinstance(sidecar['files'], dict) or set(sidecar['files']) != selected):
        fail('retained source inventory is not the complete selected Git shipping set')
    with runtime._asset(original, candidate, 'iris.tgz', completion.MAX_SOURCE) as stream, runtime._tar(
            stream, compression='gz', maximum=completion.MAX_SOURCE) as (archive, members):
        for name in sorted(selected):
            member = members.get('iris/' + name)
            if member is None or not member.isfile() or member.mode != tree[name]['mode']:
                fail('canonical source path or mode differs from selected Git')
            blob = hashlib.sha1(('blob ' + str(member.size) + '\0').encode(), usedforsecurity=False)
            digest, size = hashlib.sha256(), 0
            with archive.extractfile(member) as source:
                while block := source.read(kit.CHUNK):
                    blob.update(block)
                    digest.update(block)
                    size += len(block)
            if size != member.size or blob.hexdigest() != tree[name]['blob'] or digest.hexdigest() != sidecar['files'][name]:
                fail('canonical source bytes differ from selected Git objects')
        if runtime._member(archive, members, 'iris/VERSION', 128) != (candidate['version'] + '\n').encode('ascii'):
            fail('canonical source VERSION differs from the selected release')
    return {'commit': candidate['commit'], 'canonical_file_count': len(selected),
            'canonical_source_map_sha256': _sha(canonical(sidecar['files'])),
            'scope': 'all retained canonical source bytes and modes match the selected local Git shipping set',
            'binary_rebuild_verified': False}


def _companions(evidence):
    roles = {'aria2', 'debian', 'alpine', 'core-python', 'runtime', 'image-notices'}
    if evidence['profile'] == 'ubuntu-dependencies':
        roles.add('ubuntu')
    values = evidence['companions']
    if not isinstance(values, dict) or set(values) != roles:
        fail('exact profile companion set is required')
    result = {}
    for role, row in values.items():
        if not isinstance(row, dict):
            fail('companion evidence is invalid')
        name, digest = kit._name(row.get('asset')), kit._sha(row.get('archive_sha256'))
        if name not in evidence['files'] or evidence['files'][name]['sha256'] != digest:
            fail('companion reference differs from the closed payload inventory')
        result[role] = {'asset': name, 'sha256': digest}
    if len({row['asset'] for row in result.values()}) != len(result):
        fail('companion roles cannot alias an archive')
    return result


def _delivery_assets(payload, candidate, evidence, refs, *, destination=None):
    """Derive existing release-download assets from the checked retained source."""
    copies = {'release-auth.py': 'tools/release-auth.py',
              'aria2c-x86_64': 'deliverables/aria2c-x86_64',
              'aria2c-aarch64': 'deliverables/aria2c-aarch64', 'MANIFEST.txt': 'MANIFEST.txt'}
    aria = refs['aria2']
    with runtime._asset(payload, candidate, 'iris.tgz', completion.MAX_SOURCE) as stream, runtime._tar(
            stream, compression='gz', maximum=completion.MAX_SOURCE) as (archive, members):
        raw = {name: runtime._member(archive, members, 'iris/' + path, kit.MAX_METADATA if name in
               ('release-auth.py', 'MANIFEST.txt') else 128 * 1024**2) for name, path in copies.items()}
        # MANIFEST is generated, not a Git object. Check its complete byte map
        # before retaining the exact original bytes used by source consumers.
        expected = []
        for name, member in sorted(members.items()):
            if member.isfile() and name != 'iris/MANIFEST.txt':
                digest, _ = custody._copy(archive.extractfile(member), None, completion.MAX_SOURCE)
                expected.append(digest + '  ' + name + '\n')
        if raw['MANIFEST.txt'] != ''.join(expected).encode('utf-8'):
            fail('retained source MANIFEST differs from the complete source tar')
    pins = evidence['companions']['aria2'].get('binary_sha256')
    if (not isinstance(pins, dict) or set(pins) != {'x86_64', 'aarch64'}
            or any(_sha(raw['aria2c-' + arch]) != pins[arch] for arch in pins)):
        fail('standalone aria clients differ from independently checked source bindings')
    raw['aria2c.sha256'] = ''.join(pins[arch] + '  aria2c-' + arch + '\n'
                                  for arch in ('x86_64', 'aarch64')).encode('ascii')
    raw[aria['asset'] + '.sha256'] = (aria['sha256'] + '  ' + aria['asset'] + '\n').encode('ascii')
    raw['iris.tgz.sha256'] = (candidate['files']['iris.tgz']['sha256'] + '  iris.tgz\n').encode('ascii')
    records = {}
    for name, data in raw.items():
        if not data:
            fail('common delivery asset is empty')
        with ((destination or payload) / name).open('xb') as output:
            output.write(data)
        records[name] = {'sha256': _sha(data), 'size': len(data)}
    return records


@dataclass(frozen=True)
class CheckedCandidate:
    directory: Path
    evidence: dict
    evidence_sha256: str
    assets: dict
    companions: dict
    git_source_parity: dict
    delivery_assets: dict


@contextmanager
def check_completed_candidate(directory, expected_evidence_sha256, *, repository, tag, commit,
                              debian_keyring, pip_sdist_sha256):
    """Independently reconstruct a sealed candidate in private, with no builds."""
    kit._sha(expected_evidence_sha256)
    kit._sha(pip_sdist_sha256)
    kit._auth().validate_tag(tag)
    if not isinstance(commit, str) or not re.fullmatch('[a-f0-9]{40}', commit):
        fail('an exact external commit is required')
    tree = _git_selection(repository, tag, commit)
    work = Path('/tmp') / ('iris-prebuilt-check-' + secrets.token_hex(16))
    with custody._new_directory(work, remove=True) as descriptor:
        anchor = Path('/proc/self/fd') / str(descriptor)
        payload = work / 'payload'
        evidence, records = _snapshot_completed(directory, expected_evidence_sha256, payload,
                                                anchor / 'payload', tag, commit)
        custody._same_directory(work, descriptor)
        refs = _companions(evidence)
        original = work / 'original'
        (anchor / original.name).mkdir(mode=0o700)
        raw = regular_bytes(payload / completion.ORIGINAL, kit.MAX_METADATA)
        if _sha(raw) != evidence['original_candidate_sha256']:
            fail('original candidate seal differs from the completed evidence')
        candidate = kit._json(raw)
        if (not isinstance(candidate, dict) or not isinstance(candidate.get('files'), dict)
                or candidate.get('format') != 'iris-local-release-candidate-v1'
                or candidate.get('authenticated') is not False
                or (candidate.get('tag'), candidate.get('commit'), candidate.get('version'), candidate.get('profile'))
                != (tag, commit, tag[1:], evidence['profile'])):
            fail('original candidate inventory is invalid')
        _asset_map(candidate['files'])
        for name, row in candidate['files'].items():
            if records.get(name) != row:
                fail('original candidate asset is absent or changed in the completed set')
        for name in [*candidate['files'], completion.ORIGINAL]:
            if kit._snapshot(payload / name, anchor / original.name / name, kit.MAX_ASSET) != records[name]['sha256']:
                fail('original candidate changed while reconstructed')
        custody._same_directory(work, descriptor)
        parity = _git_source_parity(original, candidate, tree)
        arguments = {role.replace('-', '_') + '_sources': payload / refs[role]['asset']
                     for role in refs if role != 'image-notices'}
        reconstructed = completion.assemble(original, evidence['original_candidate_sha256'], work / 'reconstructed',
            tag=tag, commit=commit, image_notices=payload / refs['image-notices']['asset'],
            debian_keyring=debian_keyring, pip_sdist_sha256=pip_sdist_sha256, **arguments)
        if (completion._file(reconstructed)['sha256'] != expected_evidence_sha256
                or canonical(kit._json(regular_bytes(reconstructed, kit.MAX_METADATA))) != canonical(evidence)):
            fail('completed evidence differs from independent reconstruction')
        for name, row in records.items():
            if completion._file(payload / name) != row or completion._file(reconstructed.parent / name) != row:
                fail('completed payload changed after validation')
        if _git_selection(repository, tag, commit) != tree:
            fail('selected Git source changed during validation')
        custody._same_directory(work, descriptor)
        deliveries = _delivery_assets(payload, candidate, evidence, refs, destination=anchor / 'payload')
        records = {**records, **deliveries}
        _asset_map(records)
        custody._same_directory(work, descriptor)
        yield CheckedCandidate(payload, evidence, expected_evidence_sha256, records, refs, parity, deliveries)
        custody._same_directory(work, descriptor)


def _review(raw, checked, *, tag, commit):
    value = kit._json(raw)
    kit._keys(value, REVIEW_FIELDS)
    if (value['format'] != REVIEW_SCHEMA or value['scope'] != 'source-sufficiency-and-redistribution'
            or value['decision'] != 'approve-exact-artifacts' or (value['tag'], value['commit']) != (tag, commit)
            or value['candidate_evidence_sha256'] != checked.evidence_sha256
            or value['image_inventory_sha256'] != checked.evidence['image_inventory_sha256']
            or value['payload_asset_map_sha256'] != _sha(canonical(checked.assets))
            or canonical(value['payload_assets']) != canonical(checked.assets)
            or canonical(value['companions']) != canonical(checked.companions)):
        fail('attributed review does not bind the exact checked candidate and profile')
    for name in ('reviewer', 'reference', 'statement'):
        text = value[name]
        if (not isinstance(text, str) or not text.strip() or len(text.encode('utf-8')) > 8192
                or any(ord(char) < 32 and char not in '\n\t' or ord(char) == 127 for char in text)):
            fail('review attribution must be explicit bounded text')
    return value


def _stage(raw, tag, commit):
    value = kit._json(raw)
    kit._keys(value, {'schema', 'repository', 'workflow', 'tag', 'commit', 'run_id', 'run_attempt'})
    auth = kit._auth()
    if (value['schema'] != 'iris-release-stage-v1' or value['repository'] != auth.REPOSITORY
            or value['workflow'] != auth.WORKFLOW or (value['tag'], value['commit']) != (tag, commit)
            or any(type(value[key]) is not int or not 0 < value[key] < 2**63 for key in ('run_id', 'run_attempt'))):
        fail('explicit staged-run record does not match the selected release')
    return value


def prepare_prebuilt(directory, expected_evidence_sha256, output_dir, *, repository, tag, commit,
                     debian_keyring, pip_sdist_sha256, source_review, expected_review_sha256,
                     stage_record, expected_stage_sha256):
    """Prepare unsigned exact-byte inventories; never create an approval statement."""
    kit._sha(expected_review_sha256)
    with runtime._snapshot(source_review, expected_review_sha256, kit.MAX_METADATA) as stream:
        review_raw = stream.read(kit.MAX_METADATA + 1)
    kit._keys(kit._json(review_raw), REVIEW_FIELDS)  # Refuse malformed statements before expensive checks.
    kit._sha(expected_stage_sha256)
    with runtime._snapshot(stage_record, expected_stage_sha256, kit.MAX_METADATA) as stream:
        stage_raw = stream.read(kit.MAX_METADATA + 1)
    stage_value = _stage(stage_raw, tag, commit)
    # Input context exit guards run before publication can expose the output.
    with _publication(output_dir) as (stage, output), check_completed_candidate(
            directory, expected_evidence_sha256, repository=repository, tag=tag, commit=commit,
            debian_keyring=debian_keyring, pip_sdist_sha256=pip_sdist_sha256) as checked:
        review = _review(review_raw, checked, tag=tag, commit=commit)
        report = {'format': PREPARATION_SCHEMA, 'authenticated': False, 'source_coverage_complete': False,
                  'rebuild_verified': False, 'review_statement_authenticated': False,
                  'tag': tag, 'commit': commit, 'profile': checked.evidence['profile'],
                  'candidate_evidence_sha256': checked.evidence_sha256,
                  'payload_assets': checked.assets, 'payload_asset_map_sha256': _sha(canonical(checked.assets)),
                  'image_inventory_sha256': checked.evidence['image_inventory_sha256'],
                  'companions': checked.companions, 'git_source_parity': checked.git_source_parity,
                  'delivery_assets': checked.delivery_assets,
                  'source_review_sha256': expected_review_sha256,
                  'stage_record_sha256': expected_stage_sha256,
                  'staged_run': {key: stage_value[key] for key in ('run_id', 'run_attempt')},
                  'review_attribution': {'reviewer': review['reviewer'], 'reference': review['reference'],
                      'authority': 'Externally supplied statement; this helper checks binding, not reviewer identity or approval authority.'},
                  'remaining_gates': ['external owner-review authority', 'release authentication',
                                      'topology qualification', 'owner publication approval']}
        auth = kit._auth()
        for name, row in sorted(checked.assets.items()):
            if (completion._file(checked.directory / name) != row
                    or kit._snapshot(checked.directory / name, stage / name, kit.MAX_ASSET) != row['sha256']):
                fail('checked payload changed before unsigned publication')
        (stage / REVIEW_NAME).write_bytes(review_raw)
        (stage / STAGE_NAME).write_bytes(stage_raw)
        (stage / PREPARATION_NAME).write_bytes(canonical(report))
        additions = {REVIEW_NAME: {'sha256': expected_review_sha256, 'size': len(review_raw)},
                     STAGE_NAME: {'sha256': expected_stage_sha256, 'size': len(stage_raw)},
                     PREPARATION_NAME: {'sha256': _sha(canonical(report)), 'size': len(canonical(report))}}
        assets = {**checked.assets, **additions}
        _asset_map(assets)
        release = {'schema': 1, 'repository': auth.REPOSITORY, 'workflow': auth.WORKFLOW,
                   'tag': tag, 'commit': commit, 'assets': assets}
        release_raw = canonical(release)
        (stage / 'release.json').write_bytes(release_raw)
        checksums = {**assets, 'release.json': {'sha256': _sha(release_raw), 'size': len(release_raw)}}
        (stage / 'SHA256SUMS').write_bytes(''.join(row['sha256'] + '  ' + name + '\n'
            for name, row in sorted(checksums.items())).encode('ascii'))
    return output / PREPARATION_NAME


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--completed-dir', type=Path, required=True)
    parser.add_argument('--evidence-sha256', required=True)
    parser.add_argument('--repository', type=Path, required=True)
    parser.add_argument('--tag', required=True)
    parser.add_argument('--commit', required=True)
    parser.add_argument('--debian-keyring', type=Path, required=True)
    parser.add_argument('--pip-sdist-sha256', required=True)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument('--check', action='store_true')
    action.add_argument('--output-dir', type=Path)
    parser.add_argument('--source-review', type=Path)
    parser.add_argument('--review-sha256')
    parser.add_argument('--stage-record', type=Path)
    parser.add_argument('--stage-sha256')
    args = parser.parse_args(argv)
    external = (args.source_review, args.review_sha256, args.stage_record, args.stage_sha256)
    if args.check and any(item is not None for item in external):
        parser.error('--check is stage-independent and does not accept review or run statements')
    if not args.check and any(item is None for item in external):
        parser.error('--output-dir requires explicit source-review and stage-record inputs with their independent SHA256 pins')
    options = {name: getattr(args, name) for name in ('repository', 'tag', 'commit', 'debian_keyring', 'pip_sdist_sha256')}
    try:
        if args.check:
            with check_completed_candidate(args.completed_dir, args.evidence_sha256, **options):
                pass
            print('Technical candidate checks passed; no review authority or release authentication was established.')
        else:
            path = prepare_prebuilt(args.completed_dir, args.evidence_sha256, args.output_dir, **options,
                                    source_review=args.source_review, expected_review_sha256=args.review_sha256,
                                    stage_record=args.stage_record, expected_stage_sha256=args.stage_sha256)
            print('Unsigned preparation only; external owner-review authority and release authentication remain required: ' + str(path))
    except (InstallError, OSError, ValueError, tarfile.TarError, EOFError, zlib.error):
        parser.exit(1, 'Prebuilt preparation refused; no candidate was rebuilt, approved, signed or replaced.\n')
    return 0
