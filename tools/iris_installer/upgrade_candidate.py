# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Isolated source-build candidates for an explicitly selected installer release.

No existing deployment checkpoint is cleared. No service is started, and no
deployment identity or signing key is created. Package authentication happens
before installing the selected .deb; the retained proof binds its source bytes.
"""

import hashlib
import json
from pathlib import Path
import re
import stat

from . import deploy, managed_worker, upgrade_plan as plan
from .state import InstallError, atomic_write, regular_bytes


def selected_source(install, source, proof, expected_sha256, commit):
    source, proof = Path(source).absolute(), Path(proof).absolute()
    managed_worker._path(source)
    managed_worker._path(proof.parent)
    plan.sha256(expected_sha256)
    plan.require(isinstance(commit, str) and re.fullmatch(r'[0-9a-f]{40}', commit),
                 'Select the complete source commit from the authenticated package')
    info = proof.lstat()
    plan.require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and not info.st_mode & 0o022,
                 'Source proof must be a protected regular public file')
    raw = regular_bytes(proof, 16 * 1024 * 1024)
    plan.require(hashlib.sha256(raw).hexdigest() == expected_sha256,
                 'Source proof differs from the explicitly selected digest')
    value = json.loads(raw)
    plan.require(isinstance(value, dict) and set(value) == {'schema', 'commit', 'files'}
                 and type(value['schema']) is int and value['schema'] == 1 and value['commit'] == commit,
                 'Source proof does not describe the selected installer commit')
    manifest = plan.file_manifest(value['files'])
    plan.require(plan.canonical(manifest) == plan.canonical(deploy.source_inventory(source)),
                 'Selected package proof and shipped source inventory disagree')
    runtime = managed_worker._runtime_manifest()
    expected_runtime = {name.removeprefix('tools/iris_installer/'): digest
                        for name, digest in manifest.items() if name.startswith('tools/iris_installer/')}
    plan.worker_manifest(expected_runtime)
    plan.require(plan.canonical(runtime) == plan.canonical(expected_runtime),
                 'Run the matching installed irisctl; its runtime differs from the selected package')
    version = regular_bytes(source / 'VERSION', 100).decode('ascii').strip()
    plan.require(re.fullmatch(r'20[0-9]{2}\.[0-9]{2}\.[0-9]{2}(?:\.[0-9]+)?', version),
                 'Selected package version is invalid')
    expected_version = version + '+installer.0.g' + commit[:12]
    actual = install.command(['dpkg-query', '-W', '-f=${Status}\n${Version}\n', 'iris-installer'],
                             capture=True).decode('ascii').splitlines()
    plan.require(actual == ['install ok installed', expected_version],
                 'Install the exact selected .deb before preparing its application upgrade')
    plan.require(manifest != install.journal.document['source_manifest'],
                 'The selected application source is already installed')
    return dict(source=manifest, runtime=runtime, commit=commit, version=expected_version,
                source_proof_sha256=expected_sha256), raw


def template(install, source):
    """Render both release templates under identical existing deployment inputs."""
    from .image_storage import image_root
    public = install.command(['age-keygen', '-y', install.base / 'age.txt'], capture=True).decode().strip()
    plan.require(re.fullmatch(r'age1[0-9a-z]{58}', public), 'Current deployment age identity is invalid')
    settings = dict(install.env,
        IRIS_HOST_IP=install.config['host'],
        IRIS_AGE_KEY_FILE_HOST=str(install.base / 'age.txt'),
        IRIS_AGE_RECIPIENTS=public + ',' + install.config['recovery_recipient'],
        IRIS_GUI_PUBLISH=str(install.config['console_port']),
        IRIS_CONSOLE_URL=f'https://{install.config["console_bind"]}:{install.config["console_port"]}/',
        IRIS_PEER_TLS_MODE=install.config['peer_tls'],
        IRIS_OBSERVABILITY='1' if deploy.observability_enabled(install.config) else '',
        IRIS_IMAGE_ROOT=str(image_root(install)),
        IRIS_ARTIFACTS_HOST_DIR=str(install.base / 'artifacts'))
    value = json.loads(install.runner(['docker', 'compose', '--env-file', str(install.base / 'compose.env'),
        '-p', install.config['instance'], '-f', str(source / 'server/docker-compose.yml'),
        'config', '--format', 'json'], env=settings, capture=True))
    plan.runtime_contract(value)
    return value


def build(install, operation, selection, source):
    """Build reserved outputs only; keep old served packages and images intact."""
    directory = operation.directory
    candidate_source = install.base / ('.upgrade-source-' + operation.id)
    plan.require(not candidate_source.exists() and not candidate_source.is_symlink(),
                 'Candidate source already exists; preserve it and inspect this preparation')
    deploy.snapshot(source, candidate_source)
    # The copied source is checked against the explicit proof, not merely the
    # inventory a package supplied beside different live source bytes.
    actual = {str(path.relative_to(candidate_source)): deploy.digest(path)
              for path in candidate_source.rglob('*') if path.is_file()}
    plan.require(actual == selection['source'], 'Candidate source differs from the approved package')
    old, new = template(install, install.source), template(install, candidate_source)
    plan.require(plan.canonical(plan.runtime_contract(old)) == plan.canonical(plan.runtime_contract(new)),
                 'This release changes the runtime layout; an explicit migration is required')
    build_compose = json.loads(plan.canonical(new))
    for service in plan.SERVICES:
        build_compose['services'][service]['image'] = 'iris-upgrade/' + operation.id + ':' + service
    build_path = directory / 'build.json'
    atomic_write(build_path, plan.canonical(build_compose))
    install.command(['docker', 'compose', '-p', 'iris-upgrade-' + operation.id,
                     '-f', build_path, 'build', '--progress', 'plain'], timeout=7200)
    images = {}
    for service in plan.SERVICES:
        name = build_compose['services'][service]['image']
        records = json.loads(install.command(['docker', 'image', 'inspect', name], capture=True))
        plan.require(isinstance(records, list) and len(records) == 1, 'Candidate image identity is unavailable')
        images[service] = records[0]['Id']
    current = json.loads(regular_bytes(install.compose_file))
    compose = plan.candidate_compose(current, old, new, images)
    for spec in compose['services'].values():
        labels = spec.setdefault('labels', {})
        plan.require(isinstance(labels, dict), 'Candidate service labels must be explicit mappings')
        labels['com.cisco.iris.application-upgrade'] = operation.id
    artifacts, binary, cache = (directory / name for name in ('artifacts', 'bin', 'cache'))
    for path in (artifacts, binary, cache):
        path.mkdir(mode=0o755)
    env = dict(install.env, IRIS_ARTIFACTS_DIR=str(artifacts),
               IRIS_DEVICE_IMAGE_OCI=str(artifacts / 'device.oci.tar'),
               IRIS_DEVICE_PLATFORMS='linux/amd64,linux/arm64',
               IRIS_INSTRUCTION_ROOTS_DIR=str(install.base / 'roots'),
               XDG_CACHE_HOME=str(cache), IOXCLIENT=str(binary / 'ioxclient'))
    def run(arguments, **overrides):
        return install.runner([str(value) for value in arguments],
                              env=dict(env, **overrides), timeout=7200)
    run(['bash', candidate_source / 'tools/get-ioxclient.sh', binary])
    for architecture in ('arm64', 'amd64'):
        run(['bash', candidate_source / 'tools/stage-iox-package.sh', '--arch', architecture,
             '--artifacts-dir', artifacts])
    run(['bash', candidate_source / 'tools/build-xr-package.sh', '--out', artifacts])
    # The server image contains these helpers, but the host packer cannot read
    # that image's filesystem. Export both architectures beside the operation,
    # never into the immutable candidate source or current served directory.
    helpers = binary / 'guest-helpers'
    helpers.mkdir(mode=0o755)
    run(['bash', candidate_source / 'tools/build-ssh-verifiers.sh', helpers])
    run(['bash', candidate_source / 'tools/build-instruction-crypto.sh', helpers],
        IRIS_CRYPTO_ARCHES='amd64 arm64')
    for architecture, helper_arch, filename in (('x86_64', 'amd64', 'iris-agent.tgz'),
                                               ('aarch64', 'arm64', 'iris-agent-arm64.tgz')):
        run(['bash', candidate_source / 'server/pack-agent-bundle.sh', candidate_source / 'device',
             candidate_source / 'deliverables' / ('aria2c-' + architecture), artifacts / filename,
             '--ssh-keygen', helpers / ('ssh-keygen-' + helper_arch),
             '--instruction-roots-dir', install.base / 'roots'],
            IRIS_AEAD_HELPER=str(helpers / ('iris-aead-' + helper_arch)))
    outputs = {name: deploy.digest(artifacts / name) for name in plan.BUILD_FILES}
    plan.file_manifest(outputs, expected=plan.BUILD_FILES)
    from .upgrade_runtime import verify_files
    verify_files(candidate_source, selection['source'], closed=True)
    return {'selection': selection, 'compose': compose, 'images': images,
            'source': selection['source'], 'files': outputs,
            'source_directory': str(candidate_source), 'artifacts_directory': str(artifacts),
            'native_admission': 'not-qualified-by-this-build'}
