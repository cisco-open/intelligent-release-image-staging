# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Private package/apt fixtures only: no host package installation or network."""

from contextlib import contextmanager
from copy import deepcopy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'tools'))
from iris_installer import offline_bootstrap as subject, release_kit
from iris_installer.state import InstallError


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


loader = module('offline_bootstrap_loader', ROOT / 'tools/bootstrap-offline.py')
auth = module('offline_bootstrap_auth', ROOT / 'tools/release-auth.py')
TAG, COMMIT = 'v2026.10.09', 'a' * 40


def sha(data):
    return hashlib.sha256(data).hexdigest()


def write(path, data, mode=0o644):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    path.chmod(mode)


@pytest.fixture
def package(tmp_path):
    payload = tmp_path / 'payload'
    source = payload / subject.SOURCE
    files = {'VERSION': b'2026.10.09\n', 'LICENSE': b'license\n', 'docs/dev/installer.md': b'guide\n',
             'tools/irisctl': b'controller\n', 'tools/iris-key-setup': b'key helper\n',
             'tools/iris_installer/__init__.py': b'# module\n', 'bin/.gitkeep': b''}
    for name, data in files.items():
        write(source / name, data)
    manifest = {name: sha(data) for name, data in files.items()}
    write(source / 'INSTALLER-SOURCE.json', json.dumps(manifest).encode())
    for name, original in {subject.LIB + '/irisctl': 'tools/irisctl',
            subject.LIB + '/iris-key-setup': 'tools/iris-key-setup',
            subject.LIB + '/iris_installer/__init__.py': 'tools/iris_installer/__init__.py',
            'usr/share/doc/iris-installer/copyright': 'LICENSE',
            'usr/share/doc/iris-installer/README.md': 'docs/dev/installer.md'}.items():
        write(payload / name, files[original])
    for name, target in subject.LINKS.items():
        (payload / name).parent.mkdir(parents=True, exist_ok=True)
        (payload / name).symlink_to(target)
    for path in payload.rglob('*'):
        if path.is_dir():
            path.chmod(0o755)
    control = tmp_path / 'control'
    version = TAG[1:] + '+installer.0.g' + COMMIT[:12]
    control.write_text('Package: iris-installer\nVersion: ' + version + '\nArchitecture: amd64\n'
        'Maintainer: fixture\nSection: admin\nPriority: optional\n'
        'Depends: python3 (>= 3.12), age, ca-certificates, openssh-client\nDescription: fixture\n')
    record = subject.inspect_package(payload, control, TAG, COMMIT)
    return SimpleNamespace(payload=payload, control=control, record=record, manifest=manifest)


def test_first_verification_claims_match_existing_release_auth():
    command = loader.verify_command('/usr/bin/gh', '/private/package.deb', TAG, COMMIT, '/private/bundle', '/private/root')
    expected = auth.verify_command('/private/package.deb', TAG, COMMIT, '/private/bundle', trusted_root='/private/root')
    assert command == ['/usr/bin/gh', *expected[1:]]


@pytest.mark.parametrize('tag,commit', [('latest', COMMIT), (TAG, 'a' * 12), (TAG + '\n', COMMIT)])
def test_first_verification_rejects_moving_or_malformed_identity(tag, commit):
    with pytest.raises(loader.BootstrapError):
        loader.verify_command('/gh', '/deb', tag, commit, '/bundle', '/root')


def test_exact_shipping_inventory_includes_empty_committed_files(package):
    assert package.record['source'] == package.manifest
    assert package.record['files'][subject.SOURCE + 'bin/.gitkeep']['size'] == 0


@pytest.mark.parametrize('change', ['extra', 'source', 'runtime', 'link', 'mode', 'missing', 'version', 'dependency'])
def test_package_layout_and_source_fail_closed(package, change):
    if change == 'extra':
        write(package.payload / 'usr/bin/unexpected', b'bad')
    elif change in ('source', 'runtime'):
        path = package.payload / (subject.SOURCE + 'tools/irisctl' if change == 'source' else subject.LIB + '/irisctl')
        path.write_bytes(b'changed')
    elif change == 'link':
        path = package.payload / 'usr/bin/irisctl'
        path.unlink(); path.symlink_to('/owner/data')
    elif change == 'mode':
        (package.payload / (subject.SOURCE + 'VERSION')).chmod(0o666)
    elif change == 'missing':
        (package.payload / (subject.SOURCE + 'VERSION')).unlink()
    elif change == 'version':
        package.control.write_text(package.control.read_text().replace('installer.0', 'installer.1'))
    else:
        package.control.write_text(package.control.read_text().replace(', age,', ', curl,'))
    with pytest.raises(InstallError):
        subject.inspect_package(package.payload, package.control, TAG, COMMIT)


def archive(path, entries):
    with tarfile.open(path, 'w', format=tarfile.USTAR_FORMAT) as stream:
        for name, kind, body in entries:
            info = tarfile.TarInfo(name)
            info.mode = 0o755 if kind == 'dir' else 0o777 if kind == 'link' else 0o644
            info.type = {'file': tarfile.REGTYPE, 'dir': tarfile.DIRTYPE, 'link': tarfile.SYMTYPE,
                         'hardlink': tarfile.LNKTYPE, 'fifo': tarfile.FIFOTYPE}[kind]
            if kind in ('link', 'hardlink'):
                info.linkname = body
                stream.addfile(info)
            else:
                info.size = len(body)
                stream.addfile(info, io.BytesIO(body))


@pytest.mark.parametrize('entries,control', [
    ([('../escape', 'file', b'bad')], False),
    ([('/absolute', 'file', b'bad')], False),
    ([('usr/link', 'hardlink', 'usr/other')], False),
    ([('usr/fifo', 'fifo', b'')], False),
    ([('usr/bin/irisctl', 'link', '/owner/data')], False),
    ([('usr/a', 'file', b'a'), ('usr/a', 'file', b'b')], False),
    ([('control', 'file', b'meta'), ('postinst', 'file', b'exec')], True),
    ([('control', 'file', b'meta'), ('triggers', 'file', b'interest')], True),
])
def test_loader_refuses_unsafe_entries_and_maintainer_programs(tmp_path, entries, control):
    path = tmp_path / 'archive.tar'
    archive(path, entries)
    with pytest.raises(loader.BootstrapError):
        loader.extract(path, tmp_path / 'out', control=control)
    assert not (tmp_path / 'escape').exists()


def test_actual_deb_streams_are_safely_extracted_without_running_package(package, tmp_path):
    control = package.payload / 'DEBIAN/control'
    write(control, package.control.read_bytes())
    candidate = tmp_path / 'candidate.deb'
    subprocess.run(['dpkg-deb', '--root-owner-group', '--build', str(package.payload), str(candidate)],
                   check=True, stdout=subprocess.DEVNULL)
    for role, flag in [('control', '--ctrl-tarfile'), ('data', '--fsys-tarfile')]:
        tar = tmp_path / (role + '.tar')
        loader._command_to_file(['/usr/bin/dpkg-deb', flag, str(candidate)], tar, loader.MAX_DATA)
        loader.extract(tar, tmp_path / ('extracted-' + role), control=role == 'control')
    actual = subject.inspect_package(tmp_path / 'extracted-data', tmp_path / 'extracted-control/control', TAG, COMMIT)
    assert actual == package.record


def test_decompression_limit_kills_child_before_disk_growth(tmp_path):
    with pytest.raises(loader.BootstrapError, match='limit'):
        loader._command_to_file([sys.executable, '-I', '-c', 'import os\nwhile True: os.write(1,b"x"*4096)'],
                                tmp_path / 'bounded', 1024)
    assert (tmp_path / 'bounded').stat().st_size <= 1024


def test_snapshot_detects_copy_race_and_preserves_original(tmp_path, monkeypatch):
    source = tmp_path / 'input'
    source.write_bytes(b'original')
    read = os.read
    def race(fd, size):
        result = read(fd, size)
        if result:
            source.write_bytes(b'changed input')
        return result
    monkeypatch.setattr(loader.os, 'read', race)
    with pytest.raises(loader.BootstrapError, match='changed'):
        loader._snapshot(source, tmp_path / 'copy', 100)


def test_journal_rejects_unknown_entries_symlinks_and_parent_substitution(tmp_path):
    directory = tmp_path / 'state'
    with subject._journal(directory) as (value, save):
        assert value is None
        moved = tmp_path / 'original'
        directory.rename(moved)
        directory.mkdir(mode=0o700)
        sentinel = directory / 'bootstrap.json'
        sentinel.write_text('owner data')
        with pytest.raises(InstallError, match='directory changed'):
            save({'fixture': True})
        assert sentinel.read_text() == 'owner data'
    sentinel.unlink()
    sentinel.symlink_to(tmp_path / 'missing')
    with pytest.raises(InstallError, match='Unsafe bootstrap journal'):
        with subject._journal(directory):
            pytest.fail('Dangling journal link accepted')


def status_record(name, version='1'):
    return f'Package: {name}\nStatus: install ok installed\nArchitecture: amd64\nVersion: {version}\nDescription: fixture\n\n'


@pytest.fixture
def host(package, tmp_path, monkeypatch):
    root = tmp_path / 'host'
    for name in ('usr/lib', 'usr/bin', 'usr/share/doc', 'var/lib/dpkg/info', 'etc/dpkg'):
        (root / name).mkdir(parents=True, exist_ok=True)
    for path in [root, *root.rglob('*')]:
        path.chmod(0o755)
    status = root / 'var/lib/dpkg/status'
    baseline = status_record('owner-package')
    status.write_text(baseline)
    monkeypatch.setattr(subject, 'SYSTEM_ROOT', root)
    monkeypatch.setattr(subject, 'DPKG', status.parent)
    monkeypatch.setattr(subject, 'CONFIG', root / 'etc/dpkg')
    deb = tmp_path / 'private.deb'
    deb.write_bytes(b'authenticated package fixture')
    document = {'package': None, 'authority': {'deb': {'sha256': sha(deb.read_bytes()), 'size': deb.stat().st_size}}}
    calls, saves = [], []
    def save(value):
        saves.append(deepcopy(value))
    def install(path):
        assert path == deb and saves[-1]['package']['phase'] == 'accepted'
        calls.append('dpkg')
        shutil.copytree(package.payload / 'usr', root / 'usr', symlinks=True, dirs_exist_ok=True)
        write(status.parent / 'info/iris-installer.list', ('\n'.join(
            ['/.' , *['/' + name for name in (*package.record['files'], *package.record['directories'])]]) + '\n').encode())
        write(status.parent / 'info/iris-installer.md5sums', ('\n'.join(
            item['md5'] + '  ' + name for name, item in package.record['files'].items() if 'md5' in item) + '\n').encode())
        status.write_text(baseline + status_record('iris-installer', package.record['version']))
    monkeypatch.setattr(subject, '_install_deb', install)
    return SimpleNamespace(root=root, status=status, baseline=baseline, document=document, package=package,
                           deb=deb, calls=calls, saves=saves, save=save)


def step(host):
    subject._package_step(host.document, host.save, host.package.record, host.deb)


def test_package_install_intent_precedes_mutation_and_resume_only_checks(host):
    step(host)
    assert host.calls == ['dpkg'] and host.document['package']['phase'] == 'complete'
    host.status.write_text(host.status.read_text() + status_record('security-update'))
    step(host)
    assert host.calls == ['dpkg']


@pytest.mark.parametrize('after_effect', [False, True])
def test_interrupted_package_acceptance_retries_unchanged_or_proves_full_effect(host, monkeypatch, after_effect):
    original = subject._install_deb
    def interrupt(path):
        if after_effect:
            original(path)
        raise RuntimeError('interrupted')
    monkeypatch.setattr(subject, '_install_deb', interrupt)
    with pytest.raises(RuntimeError):
        step(host)
    assert host.document['package']['phase'] == 'accepted'
    monkeypatch.setattr(subject, '_install_deb', original)
    step(host)
    assert host.calls == ['dpkg']


@pytest.mark.parametrize('change', ['unknown-file', 'existing-package', 'orphan-info', 'foreign-link'])
def test_bootstrap_never_overwrites_or_adopts_existing_paths(host, change):
    if change == 'existing-package':
        host.status.write_text(host.baseline + status_record('iris-installer'))
    elif change == 'orphan-info':
        write(host.status.parent / 'info/iris-installer.list', b'owner metadata')
    elif change == 'foreign-link':
        (host.root / 'usr/bin/irisctl').symlink_to('/owner/path')
    else:
        write(host.root / 'usr/lib/iris-installer/sentinel', b'owner data')
    with pytest.raises(InstallError):
        step(host)
    assert host.calls == []


@pytest.mark.parametrize('change', ['missing', 'tampered', 'extra', 'partial', 'unrelated', 'deb-changed'])
def test_interrupted_or_changed_package_effect_is_never_repaired(host, monkeypatch, change):
    if change == 'deb-changed':
        host.deb.write_bytes(b'changed')
    else:
        step(host)
        host.document['package']['phase'] = 'accepted'
        path = host.root / (subject.SOURCE + 'VERSION')
        if change == 'missing':
            path.unlink()
        elif change == 'tampered':
            path.write_bytes(b'changed')
        elif change == 'extra':
            write(path.parent / 'extra', b'unknown')
        elif change == 'partial':
            host.status.write_text(host.status.read_text().replace('Status: install ok installed', 'Status: install ok unpacked'))
        else:
            host.status.write_text(host.status.read_text() + status_record('unrelated'))
    before = list(host.calls)
    with pytest.raises(InstallError):
        step(host)
    assert host.calls == before


def test_failed_acceptance_write_never_reaches_dpkg(host):
    def fail(value):
        raise OSError('disk full')
    with pytest.raises(OSError):
        subject._package_step(host.document, fail, host.package.record, host.deb)
    assert host.calls == []


@pytest.mark.parametrize('directive', ['pre-invoke=touch /sentinel', 'force-overwrite', 'path-exclude=/usr/lib/*', 'root=/other'])
def test_host_dpkg_hooks_and_override_configuration_refuse_before_apply(host, directive):
    (subject.CONFIG / 'dpkg.cfg').write_text(directive + '\n')
    with pytest.raises(InstallError, match='default dpkg configuration'):
        step(host)
    assert host.calls == []


@pytest.mark.skipif(os.geteuid() != 0, reason='Isolated dpkg root fixture requires root; never uses host package state')
@pytest.mark.parametrize('foreign_trigger', [False, True])
def test_real_dpkg_in_private_root_proves_effect_and_refuses_foreign_trigger(host, monkeypatch, tmp_path, foreign_trigger):
    package = host.package
    write(package.payload / 'DEBIAN/control', package.control.read_bytes())
    candidate = tmp_path / 'real.deb'
    subprocess.run(['dpkg-deb', '--root-owner-group', '--build', str(package.payload), str(candidate)],
                   check=True, stdout=subprocess.DEVNULL)
    shutil.copyfile(candidate, host.deb)
    host.document['authority']['deb'] = {'sha256': sha(host.deb.read_bytes()), 'size': host.deb.stat().st_size}
    baseline = host.baseline + ''.join(status_record(name, '3.12' if name == 'python3' else '1')
                                      for name in sorted(subject.ROOTS))
    host.status.write_text(baseline)
    if foreign_trigger:
        write(host.status.parent / 'triggers/File', b'/usr/lib owner-package\n')
    def install(path):
        assert host.saves[-1]['package']['phase'] == 'accepted'
        # --root is an explicit temporary fixture. No host package paths change.
        subprocess.run(['/usr/bin/dpkg', '--root=' + str(host.root), '--no-triggers', '--install', str(path)],
                       env=dict(subject.dependencies.ENV, DPKG_FRONTEND_LOCKED='1', HOME='/nonexistent'),
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    monkeypatch.setattr(subject, '_install_deb', install)
    if foreign_trigger:
        with pytest.raises(InstallError, match='partial or invalid|unrelated package state'):
            step(host)
        assert host.document['package']['phase'] == 'accepted'
    else:
        step(host)
        assert host.document['package']['phase'] == 'complete'
        subject._installed(package.record)


@pytest.fixture
def controller(host, monkeypatch, tmp_path):
    kitdir = tmp_path / 'kit'
    kitdir.mkdir()
    inventory = {'assets': {host.deb.name: host.document['authority']['deb']}}
    raw = json.dumps(inventory).encode()
    (kitdir / 'release.json').write_bytes(raw)
    kit = release_kit.VerifiedKit(kitdir, TAG, COMMIT, 'b' * 64, sha(raw),
                                  'c' * 64, 'd' * 64, True, (), 'ubuntu-dependencies')
    args = SimpleNamespace(release_kit=kitdir, release_tag=TAG, release_commit=COMMIT,
        release_verifier=Path('/independent/gh'), release_trusted_root=Path('/independent/root'),
        state_dir=tmp_path / 'bootstrap-state', deb=host.deb, accept_changes=True)
    events = []
    monkeypatch.setattr(subject.os, 'geteuid', lambda: 0)
    monkeypatch.setattr(subject, '_host', lambda: 'e' * 64)
    monkeypatch.setattr(subject, 'inspect_package', lambda *a: host.package.record)
    monkeypatch.setattr(subject.release_kit, 'verify_kit', lambda *a, **kw: events.append('authenticate') or kit)
    monkeypatch.setattr(subject, 'bind_source', lambda *a: events.append('source'))
    monkeypatch.setattr(subject, '_absent', lambda: events.append('absent'))
    # The separate private journal tests exercise its real protected FD boundary.
    journal = {'value': None}
    @contextmanager
    def state(path):
        def save(value):
            journal['value'] = deepcopy(value)
            events.append('save-' + value['dependencies']['phase'])
        yield deepcopy(journal['value']), save
    monkeypatch.setattr(subject, '_journal', state)
    closure = SimpleNamespace(digest='f' * 64)
    @contextmanager
    def prepare(value):
        assert value is kit
        events.append('closure')
        yield closure
    monkeypatch.setattr(subject.offline_inputs, 'prepare_dependencies', prepare)
    plan = {'required_roots': sorted(subject.ROOTS), 'fixture': 'exact accepted plan'}
    def planning(value, *, required_roots):
        assert value is closure and required_roots == subject.ROOTS
        events.append('plan')
        return deepcopy(plan)
    monkeypatch.setattr(subject.dependencies, 'plan_dependencies', planning)
    monkeypatch.setattr(subject.plans, 'evidence_for_plan', lambda value: {'unchanged_records_sha256': '1' * 64})
    def apply(value, accepted, evidence, *, accept_changes):
        assert accept_changes and accepted == plan and value is closure
        assert journal['value']['dependencies']['phase'] == 'accepted'
        events.append('apply')
        return {'status_sha256': '2' * 64}
    monkeypatch.setattr(subject.plans, 'apply_accepted_plan', apply)
    monkeypatch.setattr(subject.plans, 'validate_completed_plan', lambda *a: events.append('ready'))
    def package_step(document, save, package, deb, **kwargs):
        assert journal['value']['dependencies']['phase'] == 'complete'
        events.append('package')
        document['package'] = {'phase': 'complete'}
        save(document)
    monkeypatch.setattr(subject, '_package_step', package_step)
    def run():
        subject.run(args, host.deb, host.package.payload, host.package.control,
                    host.document['authority']['deb'], 'c' * 64, 'd' * 64)
    return SimpleNamespace(run=run, args=args, journal=journal, events=events, kit=kit, host=host)


def test_controller_authenticates_and_persists_exact_subset_before_apply(controller):
    controller.run()
    assert controller.events == ['authenticate', 'source', 'closure', 'absent', 'plan', 'save-accepted',
                                 'apply', 'save-complete', 'package', 'save-complete']
    controller.events.clear()
    controller.run()
    assert controller.events == ['authenticate', 'source', 'closure', 'ready', 'package', 'save-complete']


def test_preview_never_accepts_or_applies(controller):
    controller.args.accept_changes = False
    controller.run()
    assert controller.journal['value'] is None
    assert controller.events == ['authenticate', 'source', 'closure', 'absent', 'plan']


@pytest.mark.parametrize('change', ['host', 'kit', 'dependency-absent', 'null-dependency', 'subset', 'lost-plan'])
def test_resume_cannot_change_authority_or_reconstruct_lost_acceptance(controller, change):
    controller.run()
    document = controller.journal['value']
    if change in ('host', 'kit'):
        document['authority'][change] = 'changed'
    elif change == 'dependency-absent':
        document.pop('dependencies')
    elif change == 'null-dependency':
        document['dependencies'] = None
    elif change == 'subset':
        document['dependencies']['plan']['required_roots'] = ['docker.io']
    else:
        document['dependencies'].pop('plan')
    controller.events.clear()
    with pytest.raises(InstallError):
        controller.run()
    assert not {'plan', 'apply', 'package'} & set(controller.events)


def test_controller_refuses_private_deb_not_in_authenticated_inventory(controller):
    controller.host.document['authority']['deb'] = {'sha256': '9' * 64, 'size': 1}
    with pytest.raises(InstallError, match='authenticated release asset'):
        controller.run()
    assert controller.events == ['authenticate']


def test_unsupported_dpkg_configuration_precedes_prerequisite_planning(controller):
    (subject.CONFIG / 'dpkg.cfg').write_text('pre-invoke=unexpected-command\n')
    with pytest.raises(InstallError, match='default dpkg configuration'):
        controller.run()
    assert controller.events == []
    assert controller.journal['value'] is None


@pytest.fixture
def first_stage(tmp_path, monkeypatch):
    kit = tmp_path / 'kit'
    kit.mkdir()
    args = SimpleNamespace(release_kit=kit, release_tag=TAG, release_commit=COMMIT,
        release_verifier=tmp_path / 'gh', release_trusted_root=tmp_path / 'trusted-root',
        deb=tmp_path / 'installer.deb')
    events = []
    monkeypatch.setattr(loader.os, 'geteuid', lambda: 0)
    def snapshot(source, destination, maximum, **kwargs):
        destination.write_bytes(b'private verified fixture')
        return {'sha256': '1' * 64, 'size': 24}
    monkeypatch.setattr(loader, '_snapshot', snapshot)
    def command(args, destination, limit, **kwargs):
        if args[-1] == '--version':
            destination.write_bytes(b'gh version 2.82.1 (fixture)\n')
        else:
            assert events == ['authenticate'] or events == ['authenticate', 'extract-control']
            destination.write_bytes(b'bounded archive fixture')
    monkeypatch.setattr(loader, '_command_to_file', command)
    def verify(command, **kwargs):
        assert command[1:3] == ['attestation', 'verify'] and '--bundle' in command
        assert '--custom-trusted-root' in command and command.count(COMMIT) == 2
        events.append('authenticate')
    monkeypatch.setattr(loader.subprocess, 'run', verify)
    def extract(archive, destination, *, control):
        events.append('extract-control' if control else 'extract-payload')
    monkeypatch.setattr(loader, 'extract', extract)
    def import_controller(name):
        assert name == 'iris_installer.offline_bootstrap'
        assert events == ['authenticate', 'extract-control', 'extract-payload']
        events.append('import')
        return SimpleNamespace(run=lambda *a, **kw: events.append('controller'))
    monkeypatch.setattr(loader.importlib, 'import_module', import_controller)
    monkeypatch.setattr(loader.sys, 'path', list(sys.path))
    monkeypatch.setattr(loader.sys, 'dont_write_bytecode', False)
    return SimpleNamespace(args=args, events=events)


def test_loader_attests_before_extracting_or_importing_package(first_stage):
    loader.bootstrap(first_stage.args)
    assert first_stage.events == ['authenticate', 'extract-control', 'extract-payload', 'import', 'controller']


def test_failed_first_attestation_never_imports_or_extracts(first_stage, monkeypatch):
    def refuse(*a, **kw):
        raise subprocess.CalledProcessError(1, ['gh'])
    monkeypatch.setattr(loader.subprocess, 'run', refuse)
    with pytest.raises(subprocess.CalledProcessError):
        loader.bootstrap(first_stage.args)
    assert first_stage.events == []


@pytest.mark.parametrize('field', ['release_verifier', 'release_trusted_root'])
def test_kit_cannot_supply_initial_trust(first_stage, field):
    setattr(first_stage.args, field, first_stage.args.release_kit / 'self-trust')
    with pytest.raises(loader.BootstrapError, match='cannot supply'):
        loader.bootstrap(first_stage.args)
    assert first_stage.events == []


@pytest.mark.parametrize('metadata', ['iris-installer.postinst', 'iris-installer.triggers', 'iris-installer.list', 'iris-installer.md5sums'])
def test_installed_dpkg_metadata_is_part_of_exact_effect_proof(host, metadata):
    step(host)
    write(host.status.parent / ('info/' + metadata), b'changed metadata')
    with pytest.raises(InstallError, match='metadata|inventory'):
        step(host)
    assert host.calls == ['dpkg']


def test_frontend_lock_uses_posix_package_manager_locking(host):
    script = ('import fcntl,os,sys\n'
              'fd=os.open(sys.argv[1],os.O_RDWR)\n'
              'try: fcntl.lockf(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)\n'
              'except BlockingIOError: raise SystemExit(3)\n')
    with subject._frontend_lock():
        result = subprocess.run([sys.executable, '-I', '-c', script, str(host.status.parent / 'lock-frontend')])
    assert result.returncode == 3


@pytest.mark.parametrize('value', [None, False, [], 'unknown'])
def test_present_malformed_journal_never_becomes_fresh_acceptance(tmp_path, value):
    directory = tmp_path / 'state'
    directory.mkdir(mode=0o700)
    write(directory / 'bootstrap.json', json.dumps(value).encode(), mode=0o600)
    with pytest.raises(InstallError, match='no new plan was authorized'):
        with subject._journal(directory):
            pytest.fail('Malformed existing receipt was treated as absent')


def test_existing_state_without_receipt_cannot_recreate_fresh_authority(tmp_path):
    directory = tmp_path / 'state'
    with subject._journal(directory) as (value, save):
        assert value is None
    with pytest.raises(InstallError, match='no receipt'):
        with subject._journal(directory):
            pytest.fail('An interrupted or missing receipt authorized a replacement plan')


def test_outer_workspace_substitution_preserves_replacement_and_anchors_writes():
    visible = moved = None
    try:
        with pytest.raises(loader.BootstrapError, match='working directory changed'):
            with loader._workspace() as (visible, anchor, descriptor, check):
                (anchor / 'owned').write_bytes(b'private authenticated bytes')
                moved = visible.with_name(visible.name + '-moved')
                visible.rename(moved)
                visible.mkdir(mode=0o700)
                (visible / 'owned').write_bytes(b'owner sentinel')
                (anchor / 'later').write_bytes(b'still private')
                assert not (visible / 'later').exists()
                check()
        assert (visible / 'owned').read_bytes() == b'owner sentinel'
        assert list(moved.iterdir()) == []
    finally:
        # These exact paths were created by this test, never external state.
        if visible is not None:
            (visible / 'owned').unlink(missing_ok=True)
            visible.rmdir()
        if moved is not None:
            moved.rmdir()


def test_substitution_after_attestation_never_extracts_or_imports(first_stage, monkeypatch):
    paths = []
    def substitute(command, **kwargs):
        visible = Path(command[3]).resolve().parent
        moved = visible.with_name(visible.name + '-moved')
        visible.rename(moved)
        visible.mkdir(mode=0o700)
        (visible / 'sentinel').write_bytes(b'owner data')
        paths.extend((visible, moved))
        first_stage.events.append('authenticate')
    monkeypatch.setattr(loader.subprocess, 'run', substitute)
    try:
        with pytest.raises(loader.BootstrapError, match='working directory changed'):
            loader.bootstrap(first_stage.args)
        assert first_stage.events == ['authenticate']
        assert (paths[0] / 'sentinel').read_bytes() == b'owner data'
        assert list(paths[1].iterdir()) == []
    finally:
        if paths:
            (paths[0] / 'sentinel').unlink()
            paths[0].rmdir(); paths[1].rmdir()
