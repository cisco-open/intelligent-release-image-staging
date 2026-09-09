# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Instruction-signing custody uses real OpenSSH and disposable keys only."""

import base64
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import threading
import time

import pytest

import instruction_keys as keys


NOW = int(dt.datetime(2026, 9, 7, 12, tzinfo=dt.timezone.utc).timestamp())
CLI = Path(__file__).resolve().parents[1] / "iris-instructions"


def _ssh(args, *, data=None, check=True, env=None):
    clean_env = dict(os.environ if env is None else env)
    clean_env.pop("HOME", None)
    clean_env.update({"LC_ALL": "C", "TZ": "UTC"})
    return subprocess.run(
        ["ssh-keygen", *map(str, args)], input=data,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=check,
        timeout=10, env=clean_env)


def _key(path):
    path.parent.mkdir(parents=True, exist_ok=True)
    _ssh(["-q", "-t", "ed25519", "-N", "", "-C", "test-only", "-f", path])
    return path


def _stamp(epoch):
    return dt.datetime.fromtimestamp(epoch, dt.timezone.utc).strftime(
        "%Y%m%d%H%M%S")


def _issue(root, public_key, start, end, *, principals="iris-server",
           options=(), host=False):
    unique = hashlib.sha256(
        repr((str(root), start, end, principals, tuple(options), host)).encode()
    ).hexdigest()[:12]
    ceremony = public_key.parent / (public_key.stem + "-" + unique + ".pub")
    shutil.copyfile(public_key, ceremony)
    # Test-only signing later addresses the returned certificate path; mirror
    # ssh-keygen's basename lookup with a symlink to the disposable online key.
    os.symlink(str(public_key)[:-4], str(ceremony)[:-4])
    command = ["-q", "-s", root, "-I", "iris-online", "-n", principals,
               "-V", "%s:%s" % (_stamp(start), _stamp(end))]
    if host:
        command.append("-h")
    for option in options:
        command.extend(["-O", option])
    command.append(ceremony)
    _ssh(command)
    return ceremony.with_name(ceremony.stem + "-cert.pub")


def _root_map(tmp_path):
    return {"root-a": _key(tmp_path / "offline-a"),
            "root-b": _key(tmp_path / "offline-b")}


def _root_public(roots):
    return {name: Path(str(path) + ".pub") for name, path in roots.items()}


def _paths(tmp_path):
    return keys.InstructionPaths(
        state_dir=str(tmp_path / "state"),
        config_dir=str(tmp_path / "config"),
        run_dir=str(tmp_path / "run"))


def _generate(paths):
    encrypted = []
    plaintext = []

    def encrypt(plain, destination, recipients):
        assert Path(plain).name == "signing-key"
        assert str(plain).startswith(paths.run_dir)
        assert recipients == "age1test"
        plaintext.append(Path(plain).read_bytes())
        encrypted.append(hashlib.sha256(plaintext[0]).hexdigest())
        Path(destination).parent.mkdir(parents=True, exist_ok=True)
        Path(destination).write_bytes(b"test-age-ciphertext\n")
        Path(destination).chmod(0o600)

    def decrypt(ciphertext, destination, identity):
        assert Path(ciphertext).read_bytes() == b"test-age-ciphertext\n"
        assert identity == "test-mounted-identity"
        Path(destination).write_bytes(plaintext[0])

    result = keys.generate_online_key(
        paths, "age1test", identity_file="test-mounted-identity",
        encrypt_fn=encrypt, decrypt_fn=decrypt, timeout=10)
    assert encrypted and result["state"] == "generated"
    return result


def _import_cert(paths, root_public, root_private, *, start=None, end=None,
                 principals="iris-server", now=NOW):
    start = NOW - 3600 if start is None else start
    end = start + keys.CERTIFICATE_LIFETIME_SECONDS if end is None else end
    candidate = _issue(root_private, Path(paths.public_key), start, end,
                       principals=principals)
    return keys.import_online_certificate(
        paths, candidate, root_public, now=now, timeout=10)


def _allowed(path, identity, public_key, *, namespace, ca=False):
    keys.write_allowed_signers(
        path, identity, [public_key], namespace=namespace,
        certificate_authority=ca)


def _root_sign(payload, root):
    return _ssh(["-Y", "sign", "-f", root,
                 "-n", keys.KEYLIST_NAMESPACE], data=payload).stdout


def _artifact(krl, seq, issued_at, root_id, root):
    payload = keys.build_keylist_payload(
        krl, keylist_seq=seq, issued_at=issued_at,
        signer_root_id=root_id)
    return keys.assemble_keylist_artifact(payload, _root_sign(payload, root))


def _unchecked_artifact(krl, seq, issued_at, root_id, root):
    metadata = {
        "v": 1, "keylist_seq": seq, "issued_at": issued_at,
        "signer_root_id": root_id,
        "krl_sha256": hashlib.sha256(krl).hexdigest(),
    }
    encoded = json.dumps(
        metadata, sort_keys=True, separators=(",", ":")).encode()
    payload = (keys.KEYLIST_HEADER + base64.b64encode(encoded) + b"\n" +
               base64.b64encode(krl) + b"\n")
    return payload + base64.b64encode(_root_sign(payload, root)) + b"\n"


def _configure_roots(paths, roots):
    directory = Path(paths.roots_dir)
    directory.mkdir(parents=True, exist_ok=True)
    for root_id, private in roots.items():
        shutil.copyfile(str(private) + ".pub", directory / (root_id + ".pub"))


def _age_identity(tmp_path, name):
    identity = tmp_path / name
    subprocess.run(
        ["age-keygen", "-o", str(identity)], stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, check=True, timeout=10)
    recipient = subprocess.run(
        ["age-keygen", "-y", str(identity)], stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, text=True, check=True, timeout=10).stdout.strip()
    return identity, recipient


def _real_krl(tmp_path, revoked, name="revoked.krl"):
    target = tmp_path / name
    _ssh(["-q", "-k", "-f", target, revoked])
    return target.read_bytes()


def _cli_env(paths, identity=None, recipients=None):
    env = dict(os.environ, IRIS_STATE=paths.state_dir,
               IRIS_CONFIG=paths.config_dir, IRIS_RUN=paths.run_dir,
               IRIS_AGE_BIN=shutil.which("age") or "age")
    env.pop("HOME", None)
    if identity is not None:
        env["IRIS_AGE_KEY_FILE"] = str(identity)
    if recipients is not None:
        env["IRIS_AGE_RECIPIENTS"] = recipients
    return env


def _pause_ssh(monkeypatch, thread_name, predicate, *, before=False):
    entered = threading.Event()
    release = threading.Event()
    real_run = keys._run_ssh
    stopped = {"done": False}

    def interleave(args, **kwargs):
        should_pause = (threading.current_thread().name == thread_name
                        and not stopped["done"] and predicate(args, kwargs))
        if should_pause and before:
            stopped["done"] = True
            entered.set()
            assert release.wait(5)
        result = real_run(args, **kwargs)
        if should_pause and not before and result.returncode == 0:
            stopped["done"] = True
            entered.set()
            assert release.wait(5)
        return result

    monkeypatch.setattr(keys, "_run_ssh", interleave)
    return entered, release


def _start_call(name, outcomes, key, function):
    def invoke():
        try:
            outcomes[key] = function()
        except Exception as exc:
            outcomes[key + "_error"] = exc

    worker = threading.Thread(target=invoke, name=name)
    worker.start()
    return worker


def test_generate_online_key_uses_real_ssh_and_fixed_custody_paths(tmp_path):
    paths = _paths(tmp_path)
    _generate(paths)
    assert Path(paths.runtime_key).is_file()
    assert stat.S_IMODE(Path(paths.runtime_key).stat().st_mode) == 0o600
    assert Path(paths.encrypted_key).read_bytes() == b"test-age-ciphertext\n"
    public = Path(paths.public_key).read_text(encoding="ascii")
    assert public.startswith("ssh-ed25519 ")
    assert "PRIVATE" not in public
    assert Path(paths.runtime_key).parent == tmp_path / "run" / "instr"
    assert Path(paths.encrypted_key) == (
        tmp_path / "config" / "instr" / "signing-key.age")
    assert Path(paths.certificate) == (
        tmp_path / "config" / "instr" / "signing-key-cert.pub")
    assert not list(tmp_path.rglob("*root*"))


def test_generate_refuses_partial_or_existing_key_material(tmp_path):
    paths = _paths(tmp_path)
    _generate(paths)
    with pytest.raises(keys.InstructionKeyError, match="already exists"):
        _generate(paths)


def test_certificate_import_signs_exact_bytes_and_verify_time_is_openssh_time(
        tmp_path):
    paths = _paths(tmp_path)
    _generate(paths)
    roots = _root_map(tmp_path)
    root_public = _root_public(roots)
    info = _import_cert(paths, root_public, roots["root-a"])
    assert info["root_id"] == "root-a"
    assert info["principal"] == keys.ONLINE_PRINCIPAL
    assert info["lifetime_seconds"] == keys.CERTIFICATE_LIFETIME_SECONDS

    message = b"exact\x00bytes\r\nare-not-normalised\n"
    signature = keys.sign_instruction(paths, message, root_public,
                                      now=NOW, timeout=10)
    allowed = tmp_path / "iris-signers.allowed_signers"
    _allowed(allowed, keys.ONLINE_PRINCIPAL, root_public["root-a"],
             namespace=keys.INSTRUCTION_NAMESPACE, ca=True)
    signature_path = tmp_path / "message.sig"
    signature_path.write_bytes(signature)
    good = _ssh(["-Y", "verify", "-f", allowed,
                 "-I", keys.ONLINE_PRINCIPAL,
                 "-n", keys.INSTRUCTION_NAMESPACE, "-s", signature_path,
                 "-O", "verify-time=" + keys.openssh_time(NOW)], data=message,
                check=False)
    assert good.returncode == 0
    assert keys.verify_signature(
        message, signature, allowed, keys.ONLINE_PRINCIPAL,
        keys.INSTRUCTION_NAMESPACE, verify_time=NOW, timeout=10)
    assert not keys.verify_signature(
        message + b"!", signature, allowed, keys.ONLINE_PRINCIPAL,
        keys.INSTRUCTION_NAMESPACE, verify_time=NOW, timeout=10)

    epoch_time = _ssh(["-Y", "verify", "-f", allowed,
                       "-I", keys.ONLINE_PRINCIPAL,
                       "-n", keys.INSTRUCTION_NAMESPACE,
                       "-s", signature_path,
                       "-O", "verify-time=%d" % NOW], data=message,
                      check=False)
    assert epoch_time.returncode == 255


def test_import_rejects_wrong_key_principal_root_and_duplicate_root(tmp_path):
    paths = _paths(tmp_path)
    _generate(paths)
    roots = _root_map(tmp_path)
    public = _root_public(roots)

    wrong_online = _key(tmp_path / "wrong-online")
    wrong_key_cert = _issue(
        roots["root-a"], Path(str(wrong_online) + ".pub"), NOW - 1,
        NOW - 1 + keys.CERTIFICATE_LIFETIME_SECONDS)
    with pytest.raises(keys.InstructionKeyError, match="online key"):
        keys.import_online_certificate(paths, wrong_key_cert, public, now=NOW)

    wrong_principal = _issue(
        roots["root-a"], Path(paths.public_key), NOW - 1,
        NOW - 1 + keys.CERTIFICATE_LIFETIME_SECONDS,
        principals="somebody-else")
    with pytest.raises(keys.InstructionKeyError, match="principal"):
        keys.import_online_certificate(paths, wrong_principal, public, now=NOW)

    foreign = _key(tmp_path / "foreign-root")
    foreign_cert = _issue(
        foreign, Path(paths.public_key), NOW - 1,
        NOW - 1 + keys.CERTIFICATE_LIFETIME_SECONDS)
    with pytest.raises(keys.InstructionKeyError, match="configured root"):
        keys.import_online_certificate(paths, foreign_cert, public, now=NOW)

    valid = _issue(roots["root-a"], Path(paths.public_key), NOW - 1,
                   NOW - 1 + keys.CERTIFICATE_LIFETIME_SECONDS)
    duplicate = {"root-a": public["root-a"], "root-copy": public["root-a"]}
    with pytest.raises(keys.InstructionKeyError, match="exactly one"):
        keys.import_online_certificate(paths, valid, duplicate, now=NOW)


@pytest.mark.parametrize("duration", [31 * 86400, 60 * 86400, 365 * 86400])
def test_import_rejects_long_lived_online_certificate(tmp_path, duration):
    paths = _paths(tmp_path)
    _generate(paths)
    roots = _root_map(tmp_path)
    candidate = _issue(roots["root-a"], Path(paths.public_key), NOW - 60,
                       NOW - 60 + duration)
    with pytest.raises(keys.InstructionKeyError, match="30-day"):
        keys.import_online_certificate(
            paths, candidate, _root_public(roots), now=NOW)


def test_import_rejects_forever_certificate(tmp_path):
    paths = _paths(tmp_path)
    _generate(paths)
    root = _key(tmp_path / "offline")
    ceremony = tmp_path / "forever.pub"
    shutil.copyfile(paths.public_key, ceremony)
    _ssh(["-q", "-s", root, "-I", "iris-online", "-n", "iris-server",
          ceremony])
    with pytest.raises(keys.InstructionKeyError, match="finite 30-day"):
        keys.import_online_certificate(
            paths, tmp_path / "forever-cert.pub",
            {"root-a": Path(str(root) + ".pub")}, now=NOW)


@pytest.mark.parametrize("start,end", [
    (NOW + 1, NOW + 1 + keys.CERTIFICATE_LIFETIME_SECONDS),
    (NOW - keys.CERTIFICATE_LIFETIME_SECONDS - 1, NOW - 1),
])
def test_import_rejects_certificate_outside_current_validity(tmp_path, start, end):
    paths = _paths(tmp_path)
    _generate(paths)
    root = _key(tmp_path / "offline")
    candidate = _issue(root, Path(paths.public_key), start, end)
    with pytest.raises(keys.InstructionKeyError, match="validity interval"):
        keys.import_online_certificate(
            paths, candidate, {"root-a": Path(str(root) + ".pub")},
            now=NOW)


def test_certificate_lifetime_has_only_narrow_encoding_tolerance(tmp_path):
    paths = _paths(tmp_path)
    _generate(paths)
    roots = _root_map(tmp_path)
    public = _root_public(roots)
    within = keys.CERTIFICATE_LIFETIME_SECONDS + keys.CERTIFICATE_TIME_TOLERANCE
    candidate = _issue(roots["root-a"], Path(paths.public_key), NOW - 60,
                       NOW - 60 + within)
    keys.import_online_certificate(paths, candidate, public, now=NOW)
    outside = within + 1
    candidate = _issue(roots["root-a"], Path(paths.public_key), NOW - 60,
                       NOW - 60 + outside)
    with pytest.raises(keys.InstructionKeyError, match="30-day"):
        keys.import_online_certificate(paths, candidate, public, now=NOW)


def test_two_root_ca_and_bare_signer_files_are_separate_verify_any_sets(tmp_path):
    roots = _root_map(tmp_path)
    public = _root_public(roots)
    ca_allowed = tmp_path / "iris-signers.allowed_signers"
    root_allowed = tmp_path / "iris-root.allowed_signers"
    keys.write_allowed_signers(
        ca_allowed, keys.ONLINE_PRINCIPAL, list(public.values()),
        namespace=keys.INSTRUCTION_NAMESPACE, certificate_authority=True)
    ca_bytes = ca_allowed.read_bytes()
    keys.write_allowed_signers(
        root_allowed, keys.ROOT_PRINCIPAL, list(public.values()),
        namespace=keys.KEYLIST_NAMESPACE, certificate_authority=False)
    assert ca_allowed.read_bytes().count(b"\n") == 2
    assert b"cert-authority" in ca_allowed.read_bytes()
    assert root_allowed.read_bytes().count(b"\n") == 2
    assert b"cert-authority" not in root_allowed.read_bytes()

    certs = {}
    for index, name in enumerate(("root-a", "root-b"), 1):
        online = _key(tmp_path / ("online-%d" % index))
        cert = _issue(roots[name], Path(str(online) + ".pub"), NOW - 1,
                      NOW - 1 + keys.CERTIFICATE_LIFETIME_SECONDS)
        certs[name] = cert
        message = ("online-%d" % index).encode()
        sig = _ssh(["-Y", "sign", "-f", cert,
                    "-n", keys.INSTRUCTION_NAMESPACE], data=message).stdout
        assert keys.verify_signature(
            message, sig, ca_allowed, keys.ONLINE_PRINCIPAL,
            keys.INSTRUCTION_NAMESPACE, verify_time=NOW)
        root_message = ("keylist-%d" % index).encode()
        root_sig = _root_sign(root_message, roots[name])
        assert keys.verify_signature(
            root_message, root_sig, root_allowed, keys.ROOT_PRINCIPAL,
            keys.KEYLIST_NAMESPACE)
    assert ca_allowed.read_bytes() == ca_bytes

    only_a = tmp_path / "only-a"
    _allowed(only_a, keys.ONLINE_PRINCIPAL, public["root-a"],
             namespace=keys.INSTRUCTION_NAMESPACE, ca=True)
    sig_b = _ssh(["-Y", "sign", "-f", certs["root-b"],
                  "-n", keys.INSTRUCTION_NAMESPACE], data=b"other").stdout
    assert not keys.verify_signature(
        b"other", sig_b, only_a, keys.ONLINE_PRINCIPAL,
        keys.INSTRUCTION_NAMESPACE, verify_time=NOW)


def test_device_trust_renderer_is_deterministic_exact_and_verifiable(tmp_path):
    roots = _root_map(tmp_path)
    roots_dir = tmp_path / "roots.d"
    roots_dir.mkdir()
    # Deliberately create these out of lexical order. The rendered bytes must
    # use the root ID, not directory enumeration order or key comments.
    for root_id in ("root-b", "root-a"):
        public = Path(str(roots[root_id]) + ".pub").read_text().split()
        (roots_dir / (root_id + ".pub")).write_text(
            "%s %s ignored-comment\n" % (public[0], public[1]),
            encoding="ascii")
    output = tmp_path / "trust"

    keys.render_device_trust(roots_dir, output)
    ca = output / "iris-signers.allowed_signers"
    root_allowed = output / "iris-root.allowed_signers"
    canonical = {
        root_id: Path(str(roots[root_id]) + ".pub").read_text().split()[1]
        for root_id in roots
    }
    assert ca.read_text(encoding="ascii") == "".join(
        'iris-server cert-authority,namespaces="iris-instructions-v1" '
        "ssh-ed25519 %s\n" % canonical[root_id]
        for root_id in ("root-a", "root-b"))
    assert root_allowed.read_text(encoding="ascii") == "".join(
        'iris-root:%s namespaces="iris-keylist-v1" ssh-ed25519 %s\n'
        % (root_id, canonical[root_id])
        for root_id in ("root-a", "root-b"))
    assert stat.S_IMODE(ca.stat().st_mode) == 0o644
    assert stat.S_IMODE(root_allowed.stat().st_mode) == 0o644

    first = (ca.read_bytes(), root_allowed.read_bytes())
    keys.render_device_trust(roots_dir, output)
    assert (ca.read_bytes(), root_allowed.read_bytes()) == first

    for root_id in ("root-a", "root-b"):
        message = ("keylist-" + root_id).encode()
        signature = _root_sign(message, roots[root_id])
        assert keys.verify_signature(
            message, signature, root_allowed, "iris-root:" + root_id,
            keys.KEYLIST_NAMESPACE)
        assert not keys.verify_signature(
            message, signature, root_allowed, "iris-root:wrong",
            keys.KEYLIST_NAMESPACE)
        assert not keys.verify_signature(
            message, signature, root_allowed, "iris-root:" + root_id,
            keys.INSTRUCTION_NAMESPACE)


@pytest.mark.parametrize("layout", ["missing", "one", "three", "symlink-dir",
                                     "symlink-key", "unexpected", "duplicate"])
def test_device_trust_renderer_fails_closed_on_ambiguous_root_input(
        tmp_path, layout):
    roots = _root_map(tmp_path)
    real = tmp_path / "real-roots"
    roots_dir = tmp_path / "roots.d"
    if layout == "symlink-dir":
        real.mkdir()
        for root_id in roots:
            shutil.copyfile(str(roots[root_id]) + ".pub",
                            real / (root_id + ".pub"))
        roots_dir.symlink_to(real, target_is_directory=True)
    elif layout != "missing":
        roots_dir.mkdir()
        shutil.copyfile(str(roots["root-a"]) + ".pub",
                        roots_dir / "root-a.pub")
        if layout == "symlink-key":
            (roots_dir / "root-b.pub").symlink_to(
                Path(str(roots["root-b"]) + ".pub"))
        elif layout not in ("one",):
            source = roots["root-a"] if layout == "duplicate" else roots["root-b"]
            shutil.copyfile(str(source) + ".pub", roots_dir / "root-b.pub")
        if layout == "three":
            extra = _key(tmp_path / "offline-c")
            shutil.copyfile(str(extra) + ".pub", roots_dir / "root-c.pub")
        if layout == "unexpected":
            (roots_dir / "README").write_text("ambiguous input\n")

    with pytest.raises(keys.InstructionKeyError):
        keys.render_device_trust(roots_dir, tmp_path / "trust")
    assert not (tmp_path / "trust").exists()


def test_krl_empty_missing_and_revocation_by_key_and_certificate(tmp_path):
    root = _key(tmp_path / "offline")
    online = _key(tmp_path / "online")
    cert = _issue(root, Path(str(online) + ".pub"), NOW - 1,
                  NOW - 1 + keys.CERTIFICATE_LIFETIME_SECONDS)
    allowed = tmp_path / "allowed"
    _allowed(allowed, keys.ONLINE_PRINCIPAL, Path(str(root) + ".pub"),
             namespace=keys.INSTRUCTION_NAMESPACE, ca=True)
    message = b"revocation-test"
    signature = _ssh(["-Y", "sign", "-f", cert,
                      "-n", keys.INSTRUCTION_NAMESPACE], data=message).stdout
    empty = tmp_path / "empty.krl"
    empty.write_bytes(b"")
    assert keys.verify_signature(
        message, signature, allowed, keys.ONLINE_PRINCIPAL,
        keys.INSTRUCTION_NAMESPACE, krl=empty, verify_time=NOW)
    assert not keys.verify_signature(
        message, signature, allowed, keys.ONLINE_PRINCIPAL,
        keys.INSTRUCTION_NAMESPACE, krl=tmp_path / "missing.krl",
        verify_time=NOW)

    for revoked, name in ((Path(str(online) + ".pub"), "key.krl"),
                          (cert, "certificate.krl")):
        krl = tmp_path / name
        _ssh(["-q", "-k", "-f", krl, revoked])
        assert not keys.verify_signature(
            message, signature, allowed, keys.ONLINE_PRINCIPAL,
            keys.INSTRUCTION_NAMESPACE, krl=krl, verify_time=NOW)


def test_half_life_alarms_exports_public_half_and_last_seven_days_refuse_signing(
        tmp_path):
    paths = _paths(tmp_path)
    _generate(paths)
    roots = _root_map(tmp_path)
    public = _root_public(roots)
    start = NOW - 16 * 86400
    end = start + keys.CERTIFICATE_LIFETIME_SECONDS
    _import_cert(paths, public, roots["root-a"], start=start, end=end)
    status = keys.refresh_custody_status(paths, public, now=NOW)
    assert status["certificate_renewal_due"] is True
    assert status["certificate_days_to_expiry"] == 14
    assert Path(paths.public_key).is_file()
    keys.sign_instruction(paths, b"still allowed", public, now=NOW)

    start = NOW - 23 * 86400
    end = start + keys.CERTIFICATE_LIFETIME_SECONDS
    _import_cert(paths, public, roots["root-a"], start=start, end=end)
    with pytest.raises(keys.SigningUnavailable, match="last seven days"):
        keys.sign_instruction(paths, b"refused", public, now=NOW)


def test_keylist_chain_uses_previous_krl_and_root_attestation_is_verified(
        tmp_path):
    paths = _paths(tmp_path)
    roots = _root_map(tmp_path)
    public = _root_public(roots)
    initial = _artifact(b"", 1, NOW - 10, "root-a", roots["root-a"])
    first = keys.install_keylist(paths, initial, public, now=NOW)
    assert first["keylist_seq"] == 1
    assert first["verified_root_id"] == "root-a"

    revoke_a = tmp_path / "revoke-a.krl"
    _ssh(["-q", "-k", "-f", revoke_a, public["root-a"]])
    second_bytes = _artifact(
        revoke_a.read_bytes(), 2, NOW, "root-a", roots["root-a"])
    second = keys.install_keylist(paths, second_bytes, public, now=NOW)
    assert second["keylist_seq"] == 2  # candidate KRL cannot revoke its signer

    signed_by_revoked = _artifact(b"", 3, NOW + 1, "root-a", roots["root-a"])
    with pytest.raises(keys.InstructionKeyError, match="configured root"):
        keys.install_keylist(paths, signed_by_revoked, public, now=NOW + 1)
    assert Path(paths.keylist_current).read_bytes() == second_bytes

    failover = _artifact(b"", 3, NOW + 1, "root-b", roots["root-b"])
    third = keys.install_keylist(paths, failover, public, now=NOW + 1)
    assert third["verified_root_id"] == "root-b"
    state = json.loads(Path(paths.keylist_state).read_text())
    assert set(state["root_attestations"]) == {"root-a", "root-b"}
    assert "ssh-" not in json.dumps(state)


def test_keylist_claimed_root_is_never_trusted(tmp_path):
    paths = _paths(tmp_path)
    roots = _root_map(tmp_path)
    artifact = _artifact(b"", 1, NOW, "root-b", roots["root-a"])
    with pytest.raises(keys.InstructionKeyError, match="claimed root"):
        keys.install_keylist(paths, artifact, _root_public(roots), now=NOW)
    assert not Path(paths.keylist_current).exists()


def test_keylist_sequence_retry_atomicity_and_quarterly_resign(tmp_path,
                                                               monkeypatch):
    paths = _paths(tmp_path)
    roots = _root_map(tmp_path)
    public = _root_public(roots)
    artifact = _artifact(b"", 7, NOW - 90 * 86400,
                         "root-a", roots["root-a"])
    keys.install_keylist(paths, artifact, public, now=NOW)
    assert keys.install_keylist(paths, artifact, public, now=NOW)["retry"] is True
    replay_time = NOW + 120 * 86400
    assert keys.install_keylist(
        paths, artifact, public, now=replay_time)["retry"] is True
    replayed_state = json.loads(Path(paths.keylist_state).read_text())
    assert replayed_state["root_attestations"]["root-a"][
        "attested_at"] == NOW - 90 * 86400
    changed_same_seq = _artifact(
        _real_krl(tmp_path, public["root-b"], "changed-same-seq.krl"),
        7, NOW, "root-a", roots["root-a"])
    with pytest.raises(keys.InstructionKeyError, match="strictly increase"):
        keys.install_keylist(paths, changed_same_seq, public, now=NOW)
    assert keys.keylist_resign_due(paths, now=NOW) is True
    resigned = _artifact(b"", 8, NOW, "root-a", roots["root-a"])

    real_state_write = keys._atomic_write_json
    failures = {"remaining": 1}

    def fail_state(path, document, mode=0o600):
        if Path(path) == Path(paths.keylist_state) and failures["remaining"]:
            failures["remaining"] -= 1
            raise OSError("injected metadata failure")
        return real_state_write(path, document, mode=mode)

    monkeypatch.setattr(keys, "_atomic_write_json", fail_state)
    with pytest.raises(OSError, match="metadata"):
        keys.install_keylist(paths, resigned, public, now=NOW)
    # The atomically installed artifact is authoritative after the crash; stale
    # metadata cannot admit sequence 7 again, and an identical retry repairs it.
    assert Path(paths.keylist_current).read_bytes() == resigned
    with pytest.raises(keys.InstructionKeyError, match="strictly increase"):
        keys.install_keylist(paths, artifact, public, now=NOW)
    repaired = keys.install_keylist(paths, resigned, public, now=NOW)
    assert repaired["keylist_seq"] == 8 and repaired["retry"] is True
    assert json.loads(Path(paths.keylist_state).read_text())["keylist_seq"] == 8


def test_removed_root_attestation_cannot_satisfy_current_quorum(tmp_path):
    paths = _paths(tmp_path)
    roots = _root_map(tmp_path)
    public = _root_public(roots)
    keys.install_keylist(
        paths, _artifact(b"", 1, NOW - 20, "root-a", roots["root-a"]),
        public, now=NOW)
    keys.install_keylist(
        paths, _artifact(b"", 2, NOW - 10, "root-b", roots["root-b"]),
        public, now=NOW)
    Path(paths.encrypted_key).parent.mkdir(parents=True, exist_ok=True)
    Path(paths.encrypted_key).write_bytes(b"test ciphertext marker\n")

    status = keys.refresh_custody_status(
        paths, {"root-b": public["root-b"]}, now=NOW)
    assert status["roots_configured"] == 1
    assert status["roots_attested_180d"] == 1
    assert status["root_quorum_degraded"] is True


@pytest.mark.parametrize("age_days,level", [(99, "ok"), (100, "warn"),
                                             (134, "warn"), (135, "critical")])
def test_custody_status_thresholds_and_quorum_are_count_only(tmp_path, age_days,
                                                             level):
    paths = _paths(tmp_path)
    Path(paths.status).parent.mkdir(parents=True, exist_ok=True)
    status = keys.build_custody_status(
        now=NOW,
        enabled=True,
        certificate_info={
            "valid_after": NOW - 20 * 86400,
            "valid_before": NOW + 10 * 86400,
        },
        keylist_info={
            "keylist_seq": 4,
            "issued_at": NOW - age_days * 86400,
            "root_attestations": {
                "root-a": {"key_sha256": "a" * 64,
                           "attested_at": NOW - 10},
                "root-b": {"key_sha256": "b" * 64,
                           "attested_at": NOW - 181 * 86400},
            },
        },
        roots_configured=2)
    assert status["keylist_age_days"] == age_days
    assert status["root_ceremony_overdue"] == level
    assert status["roots_attested_180d"] == 1
    assert status["root_quorum_degraded"] is True
    blob = json.dumps(status, sort_keys=True)
    assert "ssh-" not in blob and "PRIVATE" not in blob and "signature" not in blob


def test_epoch_closed_schema_monotonic_locking_and_show_is_read_only(tmp_path):
    paths = _paths(tmp_path)
    assert keys.read_epoch(paths) is None
    assert not Path(paths.epoch).exists()
    assert not Path(paths.epoch_lock).exists()

    env = dict(os.environ, IRIS_STATE=paths.state_dir,
               IRIS_CONFIG=paths.config_dir, IRIS_RUN=paths.run_dir)
    env.pop("HOME", None)
    shown = subprocess.run(
        [sys.executable, str(CLI), "--show"], env=env,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        check=False, timeout=10)
    assert shown.returncode == 0
    assert json.loads(shown.stdout) == {"initialized": False}
    assert not Path(paths.epoch).exists() and not Path(paths.epoch_lock).exists()

    first = keys.new_epoch(paths, now=100)
    assert first["epoch"] == 101
    Path(paths.state_dir, "peer-policy.json").write_text(
        '{"schema":"iris-peer-policy/v1","revision":1}\n')
    Path(paths.state_dir, "peer-policy.json").unlink()
    assert keys.read_epoch(paths)["epoch"] == 101
    assert keys.new_epoch(paths, now=10)["epoch"] == 102
    assert keys.new_epoch(paths, now=1000)["epoch"] == 1001
    assert stat.S_IMODE(Path(paths.epoch).stat().st_mode) == 0o600

    values = []
    threads = [threading.Thread(
        target=lambda: values.append(keys.new_epoch(paths, now=1000)["epoch"]))
        for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert sorted(values) == list(range(1002, 1010))


@pytest.mark.parametrize("document", [
    {"schema": keys.EPOCH_SCHEMA, "epoch": True, "updated_at": 1},
    {"schema": keys.EPOCH_SCHEMA, "epoch": -1, "updated_at": 1},
    {"schema": keys.EPOCH_SCHEMA, "epoch": 1.0, "updated_at": 1},
    {"schema": keys.EPOCH_SCHEMA, "epoch": 1, "updated_at": False},
    {"schema": keys.EPOCH_SCHEMA, "epoch": 1, "updated_at": 1, "extra": 2},
    {"schema": "wrong", "epoch": 1, "updated_at": 1},
])
def test_epoch_rejects_invalid_or_open_documents(tmp_path, document):
    paths = _paths(tmp_path)
    Path(paths.epoch).parent.mkdir(parents=True)
    Path(paths.epoch).write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(keys.InstructionKeyError, match="epoch"):
        keys.read_epoch(paths)


def test_cli_new_epoch_is_executable_and_emits_no_key_material(tmp_path):
    paths = _paths(tmp_path)
    cli_mode = stat.S_IMODE(CLI.stat().st_mode)
    assert cli_mode & 0o111 == 0o111
    assert cli_mode & stat.S_IWOTH == 0
    env = dict(os.environ, IRIS_STATE=paths.state_dir,
               IRIS_CONFIG=paths.config_dir, IRIS_RUN=paths.run_dir)
    env.pop("HOME", None)
    result = subprocess.run(
        [str(CLI), "--new-epoch"], env=env,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        check=False, timeout=10)
    assert result.returncode == 0, result.stderr
    output = json.loads(result.stdout)
    assert output["schema"] == keys.EPOCH_SCHEMA and output["epoch"] > 0
    assert "PRIVATE" not in result.stdout + result.stderr
    assert not os.path.lexists(paths.runtime_key)


def test_cli_offline_keylist_round_trip_never_accepts_a_root_private_path(
        tmp_path):
    paths = _paths(tmp_path)
    root = _key(tmp_path / "offline-only")
    krl = tmp_path / "empty.krl"
    krl.write_bytes(b"")
    payload = tmp_path / "request.bin"
    signature = tmp_path / "returned.sig"
    artifact = tmp_path / "keylist.bin"
    env = dict(os.environ, IRIS_STATE=paths.state_dir,
               IRIS_CONFIG=paths.config_dir, IRIS_RUN=paths.run_dir)
    env.pop("HOME", None)
    request = subprocess.run(
        [str(CLI), "--keylist-request", str(krl), "--keylist-seq", "1",
         "--root-id", "root-a", "--output", str(payload)], env=env,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
        timeout=10)
    assert request.returncode == 0, request.stderr
    signature.write_bytes(_root_sign(payload.read_bytes(), root))
    assembled = subprocess.run(
        [str(CLI), "--assemble-keylist", str(signature),
         "--payload", str(payload), "--output", str(artifact)], env=env,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
        timeout=10)
    assert assembled.returncode == 0, assembled.stderr
    parsed = keys.parse_keylist_artifact(artifact.read_bytes())
    assert parsed["payload"] == payload.read_bytes()
    assert parsed["metadata"]["signer_root_id"] == "root-a"
    assert not os.path.lexists(paths.runtime_key)
    help_text = subprocess.run(
        [str(CLI), "--help"], env=env, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, text=True, check=False, timeout=10).stdout
    help_lower = help_text.lower()
    assert "iris-keylist-v1" in help_lower
    assert "exact unsigned bytes" in help_lower
    assert "return only the signature" in help_lower
    assert "no root private-key input" in help_lower
    assert "--root-private" not in help_text


def test_every_ssh_subprocess_has_a_timeout(tmp_path, monkeypatch):
    calls = []

    def run(*args, **kwargs):
        calls.append(kwargs)
        return subprocess.CompletedProcess(args[0], 255, b"", b"")

    monkeypatch.setattr(keys.subprocess, "run", run)
    assert not keys.verify_signature(
        b"message", b"signature", tmp_path / "allowed", "identity",
        "namespace", timeout=3)
    assert calls and calls[0]["timeout"] == 3


def test_openssh_version_is_available_without_source_pin():
    result = subprocess.run(
        ["ssh", "-V"], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, check=False, timeout=10)
    assert result.returncode == 0
    assert "OpenSSH_" in result.stdout + result.stderr


def test_management_policy_projection_reads_only_safe_durable_status(
        tmp_path, monkeypatch):
    import management_api

    paths = _paths(tmp_path)
    status = keys.build_custody_status(
        now=NOW, enabled=True,
        certificate_info={"valid_after": NOW - 20 * 86400,
                          "valid_before": NOW + 10 * 86400},
        keylist_info={"keylist_seq": 3, "issued_at": NOW - 101 * 86400,
                      "root_attestations": {
                          "root-a": {"key_sha256": "a" * 64,
                                     "attested_at": NOW - 1}}},
        roots_configured=2)
    keys.write_status(paths, status)
    monkeypatch.setattr(keys.time, "time", lambda: NOW)
    view = management_api.instruction_custody_view(paths.state_dir)
    assert view == status
    assert "root-a" not in json.dumps(view)


# Correction regressions from the sealed Task 11 static/runtime audits.


@pytest.mark.parametrize("bad_krl", [
    b"not a KRL\n",
    pytest.param(None, id="alternate-revoked-key-text"),
])
def test_correction_keylist_rejects_non_krl_without_poisoning_chain(
        tmp_path, bad_krl):
    paths = _paths(tmp_path)
    roots = _root_map(tmp_path)
    public = _root_public(roots)
    first = _artifact(b"", 1, NOW - 2, "root-a", roots["root-a"])
    keys.install_keylist(paths, first, public, now=NOW)
    if bad_krl is None:
        bad_krl = public["root-a"].read_bytes()
    poisoned = _unchecked_artifact(
        bad_krl, 2, NOW - 1, "root-a", roots["root-a"])

    with pytest.raises(keys.InstructionKeyError, match="OpenSSH KRL"):
        keys.install_keylist(paths, poisoned, public, now=NOW)
    assert Path(paths.keylist_current).read_bytes() == first
    successor = _artifact(b"", 2, NOW, "root-b", roots["root-b"])
    assert keys.install_keylist(
        paths, successor, public, now=NOW)["verified_root_id"] == "root-b"


def test_correction_keylist_caps_and_decoded_component_boundaries(
        tmp_path, monkeypatch):
    assert keys.MAX_KEYLIST_BYTES == 128 * 1024
    assert keys.MAX_KEYLIST_PAYLOAD_BYTES == 116 * 1024
    assert keys.MAX_KRL_BYTES == 80 * 1024
    assert keys.MAX_SIGNATURE_BYTES == 8 * 1024
    assert keys.MAX_METADATA_BYTES == 4 * 1024

    with monkeypatch.context() as patch:
        patch.setattr(keys, "_validate_krl_bytes", lambda *_a, **_k: None)
        keys.build_keylist_payload(
            b"x" * keys.MAX_KRL_BYTES, keylist_seq=1, issued_at=NOW,
            signer_root_id="root-a")
    with pytest.raises(keys.InstructionKeyError, match="KRL is too large"):
        keys.build_keylist_payload(
            b"x" * (keys.MAX_KRL_BYTES + 1), keylist_seq=1,
            issued_at=NOW, signer_root_id="root-a")

    payload = keys.build_keylist_payload(
        b"", keylist_seq=1, issued_at=NOW, signer_root_id="root-a")
    prefix = b"-----BEGIN SSH SIGNATURE-----\n"
    keys.assemble_keylist_artifact(
        payload, prefix + b"x" * (keys.MAX_SIGNATURE_BYTES - len(prefix)))
    with pytest.raises(keys.InstructionKeyError, match="signature is too large"):
        keys.assemble_keylist_artifact(
            payload, prefix + b"x" * (
                keys.MAX_SIGNATURE_BYTES + 1 - len(prefix)))

    with pytest.raises(keys.InstructionKeyError, match="artifact is too large"):
        keys.parse_keylist_artifact(b"x" * (keys.MAX_KEYLIST_BYTES + 1))

    oversized_metadata = base64.b64encode(
        b"{" + b" " * keys.MAX_METADATA_BYTES + b"}")
    oversized_payload = (keys.KEYLIST_HEADER + oversized_metadata + b"\n\n")
    with pytest.raises(keys.InstructionKeyError, match="metadata is too large"):
        keys._parse_keylist_payload(oversized_payload)

    metadata = {
        "v": 1, "keylist_seq": 1, "issued_at": NOW,
        "signer_root_id": "root-a",
        "krl_sha256": hashlib.sha256(
            b"x" * (keys.MAX_KRL_BYTES + 1)).hexdigest(),
    }
    meta_line = base64.b64encode(json.dumps(
        metadata, sort_keys=True, separators=(",", ":")).encode())
    oversized_krl_payload = (
        keys.KEYLIST_HEADER + meta_line + b"\n" +
        base64.b64encode(b"x" * (keys.MAX_KRL_BYTES + 1)) + b"\n")
    with pytest.raises(keys.InstructionKeyError, match="KRL is too large"):
        keys._parse_keylist_payload(oversized_krl_payload)

    oversized_signature = prefix + b"x" * (
        keys.MAX_SIGNATURE_BYTES + 1 - len(prefix))
    oversized_signature_artifact = (
        payload + base64.b64encode(oversized_signature) + b"\n")
    with pytest.raises(keys.InstructionKeyError, match="signature is too large"):
        keys.parse_keylist_artifact(oversized_signature_artifact)


def test_correction_strict_json_types_duplicates_bounds_and_parser_failures(
        tmp_path, monkeypatch):
    paths = _paths(tmp_path)
    roots = _root_map(tmp_path)
    public = _root_public(roots)
    metadata = {
        "v": 1.0, "keylist_seq": 1, "issued_at": NOW,
        "signer_root_id": "root-a", "krl_sha256": hashlib.sha256(b"").hexdigest(),
    }
    meta = json.dumps(metadata, sort_keys=True, separators=(",", ":")).encode()
    payload = keys.KEYLIST_HEADER + base64.b64encode(meta) + b"\n\n"
    artifact = payload + base64.b64encode(
        _root_sign(payload, roots["root-a"])) + b"\n"
    with pytest.raises(keys.InstructionKeyError, match="version"):
        keys.install_keylist(paths, artifact, public, now=NOW)

    Path(paths.epoch).parent.mkdir(parents=True)
    Path(paths.epoch).write_text(
        '{"schema":"%s","epoch":2000,"epoch":1,"updated_at":1}\n'
        % keys.EPOCH_SCHEMA, encoding="utf-8")
    with pytest.raises(keys.InstructionKeyError, match="duplicate"):
        keys.read_epoch(paths)

    assert keys.MAX_SERIALIZED_INTEGER < 10 ** 100
    with pytest.raises(keys.InstructionKeyError, match="sequence"):
        keys.build_keylist_payload(
            b"", keylist_seq=keys.MAX_SERIALIZED_INTEGER + 1,
            issued_at=NOW, signer_root_id="root-a")
    Path(paths.epoch).write_text(json.dumps({
        "schema": keys.EPOCH_SCHEMA,
        "epoch": keys.MAX_SERIALIZED_INTEGER + 1,
        "updated_at": 1,
    }), encoding="utf-8")
    with pytest.raises(keys.InstructionKeyError, match="epoch"):
        keys.read_epoch(paths)

    monkeypatch.setattr(keys.json, "loads", lambda *_a, **_k: (_ for _ in ()).throw(
        RecursionError("bounded parser")))
    with pytest.raises(keys.InstructionKeyError, match="epoch"):
        keys.read_epoch(paths)


def test_correction_missing_or_corrupt_established_keylist_never_bootstraps(
        tmp_path):
    paths = _paths(tmp_path)
    roots = _root_map(tmp_path)
    public = _root_public(roots)
    current = _artifact(b"", 8, NOW, "root-b", roots["root-b"])
    keys.install_keylist(paths, current, public, now=NOW)
    Path(paths.keylist_current).unlink()
    old = _artifact(b"", 7, NOW, "root-a", roots["root-a"])
    with pytest.raises(keys.InstructionKeyError, match="established.*missing"):
        keys.install_keylist(paths, old, public, now=NOW)
    assert json.loads(Path(paths.keylist_state).read_text())["keylist_seq"] == 8

    Path(paths.keylist_current).write_bytes(b"corrupt established artifact\n")
    with pytest.raises(keys.InstructionKeyError, match="keylist"):
        keys.install_keylist(
            paths, _artifact(b"", 9, NOW, "root-b", roots["root-b"]),
            public, now=NOW)


@pytest.mark.parametrize("layout", [
    "one", "three", "duplicate", "multiline", "symlink", "oversized",
    "unsupported",
])
def test_correction_production_root_discovery_requires_two_distinct_regular_keys(
        tmp_path, layout):
    paths = _paths(tmp_path)
    roots = _root_map(tmp_path)
    directory = Path(paths.roots_dir)
    directory.mkdir(parents=True)
    shutil.copyfile(str(roots["root-a"]) + ".pub", directory / "root-a.pub")
    if layout == "one":
        pass
    elif layout == "three":
        shutil.copyfile(str(roots["root-b"]) + ".pub", directory / "root-b.pub")
        third = _key(tmp_path / "offline-c")
        shutil.copyfile(str(third) + ".pub", directory / "root-c.pub")
    elif layout == "duplicate":
        shutil.copyfile(str(roots["root-a"]) + ".pub", directory / "root-b.pub")
    elif layout == "multiline":
        with (directory / "root-a.pub").open("ab") as stream:
            stream.write(Path(str(roots["root-b"]) + ".pub").read_bytes())
        shutil.copyfile(str(roots["root-b"]) + ".pub", directory / "root-b.pub")
    elif layout == "symlink":
        (directory / "root-a.pub").unlink()
        os.symlink(str(roots["root-a"]) + ".pub", directory / "root-a.pub")
        shutil.copyfile(str(roots["root-b"]) + ".pub", directory / "root-b.pub")
    elif layout == "oversized":
        with (directory / "root-a.pub").open("ab") as stream:
            stream.write(b"x" * keys.MAX_ROOT_KEY_BYTES)
        shutil.copyfile(str(roots["root-b"]) + ".pub", directory / "root-b.pub")
    else:
        rsa = tmp_path / "offline-rsa"
        _ssh(["-q", "-t", "rsa", "-b", "2048", "-N", "", "-f", rsa])
        shutil.copyfile(str(rsa) + ".pub", directory / "root-a.pub")
        shutil.copyfile(str(roots["root-b"]) + ".pub", directory / "root-b.pub")

    with pytest.raises(keys.InstructionKeyError):
        keys.discover_roots(paths)


def test_correction_attestation_is_bound_to_root_key_identity(tmp_path):
    paths = _paths(tmp_path)
    roots = _root_map(tmp_path)
    public = _root_public(roots)
    keys.install_keylist(
        paths, _artifact(b"", 1, NOW - 20, "root-a", roots["root-a"]),
        public, now=NOW)
    keys.install_keylist(
        paths, _artifact(b"", 2, NOW - 10, "root-b", roots["root-b"]),
        public, now=NOW)
    state = json.loads(Path(paths.keylist_state).read_text())
    assert set(state["root_attestations"]["root-a"]) == {
        "key_sha256", "attested_at"}
    replacement = _key(tmp_path / "replacement-b")
    Path(paths.encrypted_key).parent.mkdir(parents=True, exist_ok=True)
    Path(paths.encrypted_key).write_bytes(b"test ciphertext marker\n")
    status = keys.refresh_custody_status(
        paths, {"root-a": public["root-a"],
                "root-b": Path(str(replacement) + ".pub")}, now=NOW)
    assert status["roots_attested_180d"] == 1
    assert status["root_quorum_degraded"] is True
    assert "key_sha256" not in json.dumps(status)


def test_correction_status_freshness_duplicate_types_and_relations(tmp_path):
    paths = _paths(tmp_path)
    base = keys.build_custody_status(
        now=NOW, enabled=True, certificate_info=None,
        keylist_info=None, roots_configured=2)
    for updated_at in (NOW - 7200, NOW + 60):
        document = dict(base, updated_at=updated_at)
        keys.write_status(paths, document)
        assert keys.read_status_file(paths.status, now=NOW) == document
    for updated_at in (NOW - 7201, NOW + 61):
        keys.write_status(paths, dict(base, updated_at=updated_at))
        assert keys.read_status_file(paths.status, now=NOW) is None

    malformed = [
        dict(base, state=[]),
        dict(base, root_ceremony_overdue=[]),
        dict(base, roots_configured=3),
        dict(base, roots_attested_180d=3),
        dict(base, roots_configured=1, roots_attested_180d=2),
        dict(base, root_quorum_degraded=False),
    ]
    for document in malformed:
        Path(paths.status).write_text(json.dumps(document), encoding="utf-8")
        assert keys.read_status_file(paths.status, now=NOW) is None
    Path(paths.status).write_text(
        json.dumps(base)[:-1] + ',"state":"ready"}', encoding="utf-8")
    assert keys.read_status_file(paths.status, now=NOW) is None


def test_correction_stale_status_is_unavailable_to_management_and_telemetry(
        tmp_path, monkeypatch):
    import management_api
    from peer_registry import PeerRegistry
    import telemetry

    paths = _paths(tmp_path)
    stale = keys.build_custody_status(
        now=NOW - 7201, enabled=True, certificate_info=None,
        keylist_info=None, roots_configured=2)
    keys.write_status(paths, stale)
    monkeypatch.setattr(keys.time, "time", lambda: NOW)
    assert management_api.instruction_custody_view(paths.state_dir) is None
    hub = telemetry.Telemetry(
        PeerRegistry(), instruction_status_info=lambda: keys.read_status_file(
            paths.status))
    assert hub._instruction_status_snapshot() is None
    assert "iris_instruction_" not in hub.metrics_text()


@pytest.mark.parametrize("revoked_kind", [
    "online-key", "certificate", "issuing-root",
])
def test_correction_installed_krl_gates_import_sign_and_status(
        tmp_path, revoked_kind):
    paths = _paths(tmp_path)
    _generate(paths)
    roots = _root_map(tmp_path)
    public = _root_public(roots)
    candidate = _issue(
        roots["root-a"], Path(paths.public_key), NOW - 60,
        NOW - 60 + keys.CERTIFICATE_LIFETIME_SECONDS)
    keys.import_online_certificate(paths, candidate, public, now=NOW)
    keys.install_keylist(
        paths, _artifact(b"", 1, NOW - 1, "root-b", roots["root-b"]),
        public, now=NOW)
    revoked = {
        "online-key": Path(paths.public_key),
        "certificate": candidate,
        "issuing-root": public["root-a"],
    }[revoked_kind]
    krl = _real_krl(tmp_path, revoked, revoked_kind + ".krl")
    keys.install_keylist(
        paths, _artifact(krl, 2, NOW, "root-b", roots["root-b"]),
        public, now=NOW)

    with pytest.raises(keys.InstructionKeyError):
        keys.import_online_certificate(paths, candidate, public, now=NOW)
    with pytest.raises(keys.InstructionKeyError):
        keys.sign_instruction(paths, b"must be refused", public, now=NOW)
    status = keys.refresh_custody_status(paths, public, now=NOW)
    assert status["state"] == "invalid"


def test_correction_corrupt_established_keylist_refuses_signing(tmp_path):
    paths = _paths(tmp_path)
    _generate(paths)
    roots = _root_map(tmp_path)
    public = _root_public(roots)
    _import_cert(paths, public, roots["root-a"])
    keys.install_keylist(
        paths, _artifact(b"", 1, NOW, "root-b", roots["root-b"]),
        public, now=NOW)
    Path(paths.keylist_current).write_bytes(b"corrupt established history\n")
    with pytest.raises(keys.InstructionKeyError, match="keylist"):
        keys.sign_instruction(paths, b"must fail closed", public, now=NOW)


def test_correction_sign_uses_immutable_exact_certificate_snapshot(
        tmp_path, monkeypatch):
    paths = _paths(tmp_path)
    _generate(paths)
    roots = _root_map(tmp_path)
    public = _root_public(roots)
    _import_cert(paths, public, roots["root-a"])
    original_certificate = Path(paths.certificate).read_bytes()
    third = _key(tmp_path / "third-root")
    third_certificate = _issue(
        third, Path(paths.public_key), NOW - 60,
        NOW - 60 + keys.CERTIFICATE_LIFETIME_SECONDS)
    entered, release = _pause_ssh(
        monkeypatch, "immutable-signer",
        lambda args, _kwargs: "verify" in list(map(str, args)))
    outcome = {}
    worker = _start_call(
        "immutable-signer", outcome, "signature",
        lambda: keys.sign_instruction(
            paths, b"immutable certificate", public, now=NOW))
    assert entered.wait(5)
    keys._atomic_write(
        paths.certificate, third_certificate.read_bytes(), mode=0o644)
    release.set()
    worker.join(10)
    assert not worker.is_alive() and "signature_error" not in outcome
    signature = outcome["signature"]
    allowed_a = tmp_path / "allowed-a"
    allowed_third = tmp_path / "allowed-third"
    _allowed(allowed_a, keys.ONLINE_PRINCIPAL, public["root-a"],
             namespace=keys.INSTRUCTION_NAMESPACE, ca=True)
    _allowed(allowed_third, keys.ONLINE_PRINCIPAL,
             Path(str(third) + ".pub"),
             namespace=keys.INSTRUCTION_NAMESPACE, ca=True)
    assert keys.verify_signature(
        b"immutable certificate", signature, allowed_a,
        keys.ONLINE_PRINCIPAL, keys.INSTRUCTION_NAMESPACE, verify_time=NOW)
    assert not keys.verify_signature(
        b"immutable certificate", signature, allowed_third,
        keys.ONLINE_PRINCIPAL, keys.INSTRUCTION_NAMESPACE, verify_time=NOW)
    assert original_certificate != third_certificate.read_bytes()


def test_correction_import_commits_the_exact_validated_candidate_bytes(
        tmp_path, monkeypatch):
    paths = _paths(tmp_path)
    _generate(paths)
    roots = _root_map(tmp_path)
    public = _root_public(roots)
    candidate = _issue(
        roots["root-a"], Path(paths.public_key), NOW - 60,
        NOW - 60 + keys.CERTIFICATE_LIFETIME_SECONDS)
    validated_bytes = candidate.read_bytes()
    third = _key(tmp_path / "candidate-swap-root")
    replacement = _issue(
        third, Path(paths.public_key), NOW - 60,
        NOW - 60 + keys.CERTIFICATE_LIFETIME_SECONDS)
    entered, release = _pause_ssh(
        monkeypatch, "certificate-import",
        lambda args, _kwargs: "verify" in list(map(str, args)))
    outcome = {}
    worker = _start_call(
        "certificate-import", outcome, "info",
        lambda: keys.import_online_certificate(
            paths, candidate, public, now=NOW))
    assert entered.wait(5)
    candidate.write_bytes(replacement.read_bytes())
    release.set()
    worker.join(10)
    assert not worker.is_alive() and "info_error" not in outcome
    assert outcome["info"]["root_id"] == "root-a"
    assert Path(paths.certificate).read_bytes() == validated_bytes


def test_correction_certificate_import_is_serialized_with_signing(
        tmp_path, monkeypatch):
    paths = _paths(tmp_path)
    _generate(paths)
    roots = _root_map(tmp_path)
    public = _root_public(roots)
    _import_cert(paths, public, roots["root-a"])
    short = _issue(
        roots["root-b"], Path(paths.public_key),
        NOW - 24 * 86400, NOW + 6 * 86400)
    entered, release = _pause_ssh(
        monkeypatch, "locked-signer",
        lambda args, _kwargs: "verify" in list(map(str, args)))
    imported = threading.Event()
    outcomes = {}

    def run_import():
        try:
            outcomes["import"] = keys.import_online_certificate(
                paths, short, public, now=NOW)
        except Exception as exc:
            outcomes["import_error"] = exc
        finally:
            imported.set()

    signer = _start_call(
        "locked-signer", outcomes, "signature",
        lambda: keys.sign_instruction(
            paths, b"serialized certificate", public, now=NOW))
    assert entered.wait(5)
    importer = threading.Thread(target=run_import, name="concurrent-import")
    importer.start()
    completed_during_sign = imported.wait(0.3)
    release.set()
    signer.join(10)
    importer.join(10)
    assert not signer.is_alive() and not importer.is_alive()
    assert not completed_during_sign
    assert "signature_error" not in outcomes \
        and "import_error" not in outcomes


def test_correction_revocation_update_is_serialized_with_actual_signature(
        tmp_path, monkeypatch):
    paths = _paths(tmp_path)
    _generate(paths)
    roots = _root_map(tmp_path)
    public = _root_public(roots)
    _import_cert(paths, public, roots["root-a"])
    keys.install_keylist(
        paths, _artifact(b"", 1, NOW - 1, "root-b", roots["root-b"]),
        public, now=NOW)
    krl = _real_krl(tmp_path, Path(paths.public_key), "race.krl")
    revocation = _artifact(krl, 2, NOW, "root-b", roots["root-b"])
    entered, release = _pause_ssh(
        monkeypatch, "revocation-signer",
        lambda _args, kwargs: kwargs.get("data") == b"revocation race",
        before=True)
    installed = threading.Event()
    outcomes = {}

    def run_install():
        try:
            outcomes["install"] = keys.install_keylist(
                paths, revocation, public, now=NOW)
        except Exception as exc:
            outcomes["install_error"] = exc
        finally:
            installed.set()

    signer = _start_call(
        "revocation-signer", outcomes, "signature",
        lambda: keys.sign_instruction(
            paths, b"revocation race", public, now=NOW))
    assert entered.wait(5)
    installer = threading.Thread(target=run_install, name="revocation-installer")
    installer.start()
    completed_during_sign = installed.wait(0.3)
    release.set()
    signer.join(10)
    installer.join(10)
    assert not signer.is_alive() and not installer.is_alive()
    assert not completed_during_sign
    assert "signature_error" not in outcomes \
        and "install_error" not in outcomes


def test_correction_generation_rejects_unrecoverable_recipient_and_cleans(
        tmp_path):
    paths = _paths(tmp_path)
    identity_a, _recipient_a = _age_identity(tmp_path, "age-a")
    _identity_b, recipient_b = _age_identity(tmp_path, "age-b")
    with pytest.raises(keys.InstructionKeyError, match="recover"):
        keys.generate_online_key(
            paths, recipient_b, identity_file=identity_a,
            timeout=10)
    for target in (
            paths.runtime_key, paths.runtime_key + ".pub",
            paths.encrypted_key, paths.public_key, paths.certificate,
            paths.runtime_certificate):
        assert not os.path.lexists(target)


def test_correction_generation_publication_failure_restores_absence_and_retries(
        tmp_path, monkeypatch):
    paths = _paths(tmp_path)
    identity = tmp_path / "mounted-identity"
    identity.write_text("test identity marker\n", encoding="ascii")

    def encrypt(plain, destination, recipients):
        assert recipients == "age1test"
        Path(destination).parent.mkdir(parents=True, exist_ok=True)
        Path(destination).write_bytes(b"test-ciphertext\n" + Path(plain).read_bytes())

    def decrypt(ciphertext, destination, mounted_identity):
        assert Path(mounted_identity) == identity
        data = Path(ciphertext).read_bytes()
        assert data.startswith(b"test-ciphertext\n")
        Path(destination).parent.mkdir(parents=True, exist_ok=True)
        Path(destination).write_bytes(data.split(b"\n", 1)[1])

    targets = (
        paths.runtime_key, paths.runtime_key + ".pub", paths.encrypted_key,
        paths.public_key, paths.certificate, paths.runtime_certificate,
    )
    real_publish = keys._publish_owned

    def fail_publication(path, data, mode, owned):
        if Path(path) == Path(paths.public_key):
            raise OSError("injected publication failure")
        return real_publish(path, data, mode, owned)

    with monkeypatch.context() as patch:
        patch.setattr(keys, "_publish_owned", fail_publication)
        with pytest.raises(
                keys.InstructionKeyError, match="setup|generation|recover"):
            keys.generate_online_key(
                paths, "age1test", identity_file=identity,
                encrypt_fn=encrypt, decrypt_fn=decrypt, timeout=10)
    assert all(not os.path.lexists(target) for target in targets)
    assert not [path for path in tmp_path.rglob("*")
                if "generation" in path.name or path.name.endswith(".tmp")]

    result = keys.generate_online_key(
        paths, "age1test", identity_file=identity,
        encrypt_fn=encrypt, decrypt_fn=decrypt, timeout=10)
    assert result["state"] == "generated"


def test_correction_cold_cli_loads_export_import_status_and_install(tmp_path):
    paths = _paths(tmp_path)
    identity, recipient = _age_identity(tmp_path, "cold identity")
    roots = _root_map(tmp_path)
    _configure_roots(paths, roots)
    env = _cli_env(paths, identity, recipient)
    generated = subprocess.run(
        [str(CLI), "--generate-online-key"], env=env,
        cwd=tmp_path, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, check=False, timeout=15)
    assert generated.returncode == 0, generated.stderr
    durable_public = Path(paths.public_key).read_bytes()

    for target in (paths.runtime_key, paths.runtime_key + ".pub"):
        Path(target).unlink()
    exported = tmp_path / "exported public.pub"
    result = subprocess.run(
        [str(CLI), "--export-public", str(exported)], env=env,
        cwd=tmp_path, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, check=False, timeout=15)
    assert result.returncode == 0, result.stderr
    assert exported.read_bytes() == durable_public
    assert stat.S_IMODE(Path(paths.runtime_key).stat().st_mode) == 0o600

    for target in (paths.runtime_key, paths.runtime_key + ".pub"):
        Path(target).unlink(missing_ok=True)
    now = int(time.time())
    candidate = _issue(
        roots["root-a"], Path(paths.public_key), now - 60,
        now - 60 + keys.CERTIFICATE_LIFETIME_SECONDS)
    imported = subprocess.run(
        [str(CLI), "--import-certificate", str(candidate)], env=env,
        cwd=tmp_path, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, check=False, timeout=15)
    assert imported.returncode == 0, imported.stderr
    assert Path(paths.runtime_key).is_file()

    for target in (paths.runtime_key, paths.runtime_key + ".pub"):
        Path(target).unlink(missing_ok=True)
    status = subprocess.run(
        [str(CLI), "--status"], env=env, cwd=tmp_path,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        check=False, timeout=15)
    assert status.returncode == 0, status.stderr
    assert Path(paths.runtime_key).is_file()

    for target in (paths.runtime_key, paths.runtime_key + ".pub"):
        Path(target).unlink(missing_ok=True)
    artifact = tmp_path / "cold-keylist"
    artifact.write_bytes(_artifact(
        b"", 1, int(time.time()), "root-b", roots["root-b"]))
    installed = subprocess.run(
        [str(CLI), "--install-keylist", str(artifact)], env=env,
        cwd=tmp_path, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, check=False, timeout=15)
    assert installed.returncode == 0, installed.stderr
    assert Path(paths.runtime_key).is_file()


def test_second_correction_failed_cache_publication_preserves_certificate(
        tmp_path, monkeypatch):
    paths = _paths(tmp_path)
    _generate(paths)
    roots = _root_map(tmp_path)
    public = _root_public(roots)
    _import_cert(paths, public, roots["root-a"])
    previous_durable = hashlib.sha256(
        Path(paths.certificate).read_bytes()).hexdigest()
    previous_cache = hashlib.sha256(
        Path(paths.runtime_certificate).read_bytes()).hexdigest()
    candidate = _issue(
        roots["root-b"], Path(paths.public_key),
        NOW - 24 * 86400, NOW + 6 * 86400)
    real_atomic_write = keys._atomic_write

    def fail_runtime_cache(path, data, mode=0o600):
        if Path(path) == Path(paths.runtime_certificate):
            raise OSError("injected runtime cache publication failure")
        return real_atomic_write(path, data, mode=mode)

    monkeypatch.setattr(keys, "_atomic_write", fail_runtime_cache)
    try:
        keys.import_online_certificate(paths, candidate, public, now=NOW)
    except Exception as exc:  # Assert the stable public error below.
        caught = exc
    else:
        pytest.fail("certificate import unexpectedly succeeded")

    assert hashlib.sha256(Path(paths.certificate).read_bytes()).hexdigest() == \
        previous_durable
    assert hashlib.sha256(
        Path(paths.runtime_certificate).read_bytes()).hexdigest() == \
        previous_cache
    assert type(caught) is keys.InstructionKeyError
    assert str(caught) == "online certificate publication failed"


@pytest.mark.parametrize("certificate_kind", ["critical-option", "host"])
def test_second_correction_import_requires_unconstrained_user_certificate(
        tmp_path, certificate_kind):
    paths = _paths(tmp_path)
    _generate(paths)
    roots = _root_map(tmp_path)
    candidate = _issue(
        roots["root-a"], Path(paths.public_key), NOW - 60,
        NOW - 60 + keys.CERTIFICATE_LIFETIME_SECONDS,
        options=("critical:audit-unsupported=required",)
        if certificate_kind == "critical-option" else (),
        host=certificate_kind == "host")
    expected = "critical" if certificate_kind == "critical-option" else "user"
    with pytest.raises(keys.InstructionKeyError, match=expected):
        keys.import_online_certificate(
            paths, candidate, _root_public(roots), now=NOW)


@pytest.mark.parametrize("malformation", [
    "missing-sections", "duplicate-type", "duplicate-critical",
    "hidden-critical-body",
])
def test_second_correction_certificate_detail_parser_fails_closed(
        tmp_path, monkeypatch, malformation):
    type_lines = (
        b"        Type: ssh-ed25519-cert-v01@openssh.com user certificate\n")
    critical_lines = b"        Critical Options: (none)\n"
    if malformation == "missing-sections":
        type_lines = b""
        critical_lines = b""
    elif malformation == "duplicate-type":
        type_lines += b"        Type: malformed future certificate header\n"
    elif malformation == "duplicate-critical":
        critical_lines += b"        Critical Options: malformed\n"
    else:
        critical_lines += b"                audit-unsupported required\n"
    details = (
        b"test-cert.pub:\n" + type_lines
        + b"        Valid: from 2026-09-07T11:59:00 "
        b"to 2026-10-07T11:59:00\n"
        b"        Principals:\n"
        b"                iris-server\n"
        + critical_lines
        + b"        Extensions: (none)\n")

    def incomplete_details(args, **_kwargs):
        return subprocess.CompletedProcess(args, 0, details, b"")

    monkeypatch.setattr(keys, "_run_ssh", incomplete_details)
    with pytest.raises(keys.InstructionKeyError, match="certificate"):
        keys._certificate_fields(tmp_path / "unused-certificate")


def _second_correction_ready_status():
    attestations = {
        "root-a": {"key_sha256": "a" * 64, "attested_at": NOW},
        "root-b": {"key_sha256": "b" * 64, "attested_at": NOW},
    }
    return keys.build_custody_status(
        now=NOW, enabled=True,
        certificate_info={
            "valid_after": NOW - 60,
            "valid_before": NOW - 60 + keys.CERTIFICATE_LIFETIME_SECONDS,
        },
        keylist_info={
            "keylist_seq": 1, "issued_at": NOW,
            "root_attestations": attestations,
        },
        roots_configured=2)


@pytest.mark.parametrize("case", ["negative-ready", "phase0-flags"])
def test_second_correction_status_contradictions_are_unavailable_to_projections(
        tmp_path, monkeypatch, case):
    import management_api
    from peer_registry import PeerRegistry
    import telemetry

    paths = _paths(tmp_path)
    if case == "negative-ready":
        document = dict(
            _second_correction_ready_status(),
            certificate_days_to_expiry=-1)
    else:
        document = dict(keys.build_custody_status(
            now=NOW, enabled=False, certificate_info=None,
            keylist_info=None, roots_configured=0))
        document.update(
            certificate_renewal_due=True, signing_refused=True)
    Path(paths.status).parent.mkdir(parents=True)
    Path(paths.status).write_text(json.dumps(document), encoding="utf-8")
    monkeypatch.setattr(keys.time, "time", lambda: NOW)
    assert management_api.instruction_custody_view(paths.state_dir) is None
    hub = telemetry.Telemetry(
        PeerRegistry(), instruction_status_info=lambda: keys.read_status_file(
            paths.status, now=NOW))
    assert hub._instruction_status_snapshot() is None
    assert "iris_instruction_" not in hub.metrics_text()


@pytest.mark.parametrize("case", ["flags-without-certificate",
                                   "refusal-without-renewal"])
def test_second_correction_status_validator_rejects_impossible_flags(
        tmp_path, case):
    paths = _paths(tmp_path)
    if case == "flags-without-certificate":
        document = dict(keys.build_custody_status(
            now=NOW, enabled=True, certificate_info=None,
            keylist_info=None, roots_configured=2),
            certificate_renewal_due=True, signing_refused=True)
    else:
        document = dict(keys.build_custody_status(
            now=NOW, enabled=True,
            certificate_info={
                "valid_after": NOW - 24 * 86400,
                "valid_before": NOW + 6 * 86400,
            }, keylist_info=None, roots_configured=2),
            certificate_renewal_due=False)
    with pytest.raises(keys.InstructionKeyError, match="status"):
        keys.write_status(paths, document)
    assert not Path(paths.status).exists()


def test_second_correction_status_preserves_phase0_and_state_ordering():
    phase0 = keys.build_custody_status(
        now=NOW, enabled=False, certificate_info=None,
        keylist_info=None, roots_configured=2)
    assert keys._validate_status(phase0) == phase0
    assert phase0["state"] == "phase0"
    assert phase0["roots_attested_180d"] == 0
    assert all(not phase0[field] for field in (
        "certificate_renewal_due", "signing_refused",
        "keylist_resign_due", "root_quorum_degraded"))

    for valid_after, renewal_due in (
            (NOW - 60, False), (NOW - 20 * 86400, True)):
        status = keys.build_custody_status(
            now=NOW, enabled=True,
            certificate_info={
                "valid_after": valid_after,
                "valid_before": valid_after
                + keys.CERTIFICATE_LIFETIME_SECONDS,
            }, keylist_info=None, roots_configured=2)
        assert status["state"] == "keylist_missing"
        assert status["certificate_renewal_due"] is renewal_due
        assert keys._validate_status(status) == status


def test_second_correction_root_alias_is_one_stable_identity(tmp_path):
    paths = _paths(tmp_path)
    root = _key(tmp_path / "canonical-root")
    fields = Path(str(root) + ".pub").read_text(encoding="ascii").split()
    directory = Path(paths.roots_dir)
    directory.mkdir(parents=True)
    canonical = (fields[0] + " " + fields[1] + "\n").encode("ascii")
    padded = (fields[0] + " " + fields[1] + "=\n").encode("ascii")
    first = directory / "root-a.pub"
    second = directory / "root-b.pub"
    first.write_bytes(canonical)
    second.write_bytes(padded)

    with pytest.raises(keys.InstructionKeyError, match="exactly one"):
        keys.discover_roots(paths)
    assert keys._public_key_bytes(first) == keys._public_key_bytes(second)
    assert keys._root_digest(first) == keys._root_digest(second)
    first_allowed = tmp_path / "first.allowed"
    second_allowed = tmp_path / "second.allowed"
    keys.write_allowed_signers(
        first_allowed, keys.ROOT_PRINCIPAL, [first],
        namespace=keys.KEYLIST_NAMESPACE, certificate_authority=False)
    keys.write_allowed_signers(
        second_allowed, keys.ROOT_PRINCIPAL, [second],
        namespace=keys.KEYLIST_NAMESPACE, certificate_authority=False)
    assert first_allowed.read_bytes() == second_allowed.read_bytes()


def test_second_correction_cleanup_continues_after_owned_unlink_failure(
        tmp_path, monkeypatch):
    paths = _paths(tmp_path)
    identity = tmp_path / "mounted-identity"
    identity.write_text("test identity marker\n", encoding="ascii")

    def encrypt(plain, destination, _recipients):
        Path(destination).write_bytes(
            b"test-ciphertext\n" + Path(plain).read_bytes())

    def decrypt(ciphertext, destination, _identity):
        Path(destination).write_bytes(
            Path(ciphertext).read_bytes().split(b"\n", 1)[1])

    real_move = keys._move_owned
    real_unlink = keys.os.unlink
    real_fsync_directory = keys._fsync_directory
    cleanup = {"active": False, "failed": False}
    attempts = []
    cleanup_fsyncs = []
    expected = {
        os.path.abspath(paths.runtime_key + ".pub"),
        os.path.abspath(paths.public_key),
        os.path.abspath(paths.encrypted_key),
    }

    def fail_final_publication(source, destination, mode, owned):
        if Path(destination) == Path(paths.runtime_key):
            cleanup["active"] = True
            raise OSError("injected primary publication failure")
        return real_move(source, destination, mode, owned)

    def fail_one_cleanup_unlink(path, *args, **kwargs):
        target = os.path.abspath(os.fspath(path))
        if cleanup["active"] and target in expected:
            attempts.append(target)
            if target == os.path.abspath(paths.runtime_key + ".pub") \
                    and not cleanup["failed"]:
                cleanup["failed"] = True
                raise OSError("injected cleanup unlink failure")
        return real_unlink(path, *args, **kwargs)

    def record_cleanup_fsync(directory):
        if cleanup["active"]:
            cleanup_fsyncs.append(os.path.abspath(os.fspath(directory)))
        return real_fsync_directory(directory)

    monkeypatch.setattr(keys, "_move_owned", fail_final_publication)
    monkeypatch.setattr(keys.os, "unlink", fail_one_cleanup_unlink)
    monkeypatch.setattr(keys, "_fsync_directory", record_cleanup_fsync)
    with pytest.raises(keys.InstructionKeyError, match="setup"):
        keys.generate_online_key(
            paths, "age1test", identity_file=identity,
            encrypt_fn=encrypt, decrypt_fn=decrypt, timeout=10)

    assert set(attempts) == expected
    assert not Path(paths.encrypted_key).exists()
    assert not Path(paths.public_key).exists()
    assert Path(paths.runtime_key + ".pub").exists()
    assert not Path(paths.runtime_key).exists()
    assert os.path.abspath(Path(paths.encrypted_key).parent) in cleanup_fsyncs
    # The injected failure is not claimed recoverable; remove the disposable
    # fixture directly so pytest can delete its temporary directory.
    real_unlink(paths.runtime_key + ".pub")


def test_second_correction_huge_epoch_clock_has_stable_error(tmp_path):
    paths = _paths(tmp_path)
    with pytest.raises(
            keys.InstructionKeyError,
            match="instruction epoch clock is invalid"):
        keys.new_epoch(paths, now=10 ** 1000)
    assert not Path(paths.state_dir).exists()


def _task14_installed_keylist(tmp_path):
    """A real root-signed, installed fixture; GET does not repeat custody."""
    paths = _paths(tmp_path)
    roots = _root_map(tmp_path)
    artifact = _artifact(b"", 8, NOW, "root-a", roots["root-a"])
    keys.install_keylist(paths, artifact, _root_public(roots), now=NOW)
    return paths, roots, artifact


def test_task14_keylist_snapshot_exact_bytes_sequence_digest_and_copies(tmp_path):
    read = keys.read_keylist_snapshot
    paths, _roots, artifact = _task14_installed_keylist(tmp_path)
    expected = {"bytes": artifact, "keylist_seq": 8,
                "artifact_sha256": hashlib.sha256(artifact).hexdigest()}
    first = read(paths)
    assert first == expected
    first["keylist_seq"] = 100
    first["bytes"] = b"caller replacement"
    assert read(paths) == expected


def test_task14_keylist_snapshot_uninitialized_and_lost_established(tmp_path):
    read = keys.read_keylist_snapshot
    assert read(_paths(tmp_path / "fresh")) is None
    paths, _roots, _artifact_bytes = _task14_installed_keylist(tmp_path / "used")
    Path(paths.keylist_current).unlink()
    with pytest.raises(keys.InstructionKeyError):
        read(paths)


@pytest.mark.parametrize("metadata_state", ["absent", "behind"])
def test_task14_keylist_snapshot_artifact_authoritative_crash_states(
        tmp_path, metadata_state):
    read = keys.read_keylist_snapshot
    paths, roots, _old = _task14_installed_keylist(tmp_path)
    newer = _artifact(b"", 9, NOW + 1, "root-a", roots["root-a"])
    Path(paths.keylist_current).write_bytes(newer)
    if metadata_state == "absent":
        Path(paths.keylist_state).unlink()
    before = (Path(paths.keylist_state).read_bytes()
              if Path(paths.keylist_state).exists() else None)
    snapshot = read(paths)
    assert snapshot == {"bytes": newer, "keylist_seq": 9,
                        "artifact_sha256": hashlib.sha256(newer).hexdigest()}
    assert (Path(paths.keylist_state).read_bytes()
            if Path(paths.keylist_state).exists() else None) == before


@pytest.mark.parametrize("damage", [
    "state-ahead", "artifact-digest", "krl-digest", "issued-at", "root-id",
    "artifact-malformed", "artifact-oversize", "state-malformed",
    "state-oversize", "artifact-directory", "state-directory",
])
def test_task14_keylist_snapshot_rejects_corruption_and_contradictions(
        tmp_path, damage):
    read = keys.read_keylist_snapshot
    paths, _roots, _artifact_bytes = _task14_installed_keylist(tmp_path)
    artifact_path, state_path = Path(paths.keylist_current), Path(paths.keylist_state)
    state = json.loads(state_path.read_text())
    if damage == "state-ahead":
        state["keylist_seq"] += 1
    elif damage == "artifact-digest":
        state["artifact_sha256"] = "0" * 64
    elif damage == "krl-digest":
        state["krl_sha256"] = "0" * 64
    elif damage == "issued-at":
        state["issued_at"] -= 1
    elif damage == "root-id":
        state["verified_root_id"] = "root-b"
        state["root_attestations"]["root-b"] = dict(
            state["root_attestations"]["root-a"])
    if damage in {"state-ahead", "artifact-digest", "krl-digest", "issued-at", "root-id"}:
        state_path.write_text(json.dumps(state))
    elif damage == "artifact-malformed":
        artifact_path.write_bytes(b"not a keylist\n")
    elif damage == "artifact-oversize":
        artifact_path.write_bytes(b"x" * (keys.MAX_KEYLIST_BYTES + 1))
    elif damage == "state-malformed":
        state_path.write_text('{"keylist_seq":8,"keylist_seq":9}')
    elif damage == "state-oversize":
        state_path.write_bytes(b" " * (keys.MAX_METADATA_BYTES + 1))
    else:
        target = artifact_path if damage == "artifact-directory" else state_path
        target.unlink()
        target.mkdir()
    with pytest.raises(keys.InstructionKeyError):
        read(paths)


def test_task14_keylist_snapshot_holds_custody_lock_and_does_not_reverify_or_write(
        tmp_path, monkeypatch):
    import fcntl

    read = keys.read_keylist_snapshot
    paths, _roots, artifact = _task14_installed_keylist(tmp_path)
    protected = [Path(paths.keylist_current), Path(paths.keylist_state)]
    before = {p: (p.read_bytes(), p.stat().st_mtime_ns) for p in protected}
    real_parse = keys.parse_keylist_artifact
    real_state = keys._read_keylist_state
    calls = []

    def assert_locked():
        with open(paths.keylist_lock, "rb") as independent:
            with pytest.raises(BlockingIOError):
                fcntl.flock(independent.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)

    def locked_parse(value):
        assert_locked()
        calls.append("artifact")
        return real_parse(value)

    def locked_state(path):
        assert_locked()
        calls.append("state")
        return real_state(path)

    def forbidden(*_args, **_kwargs):
        pytest.fail("snapshot must not repeat or mutate root custody")

    monkeypatch.setattr(keys, "parse_keylist_artifact", locked_parse)
    monkeypatch.setattr(keys, "_read_keylist_state", locked_state)
    for name in ("discover_roots", "verify_signature", "install_keylist",
                 "sign_instruction", "_atomic_write", "_atomic_write_json"):
        monkeypatch.setattr(keys, name, forbidden)
    assert read(paths)["bytes"] == artifact
    assert calls == ["artifact", "state"]
    assert {p: (p.read_bytes(), p.stat().st_mtime_ns) for p in protected} == before
    with open(paths.keylist_lock, "rb") as independent:
        fcntl.flock(independent.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        fcntl.flock(independent.fileno(), fcntl.LOCK_UN)


def test_task14_keylist_snapshot_unreadable_state_is_not_uninitialized(
        tmp_path, monkeypatch):
    read = keys.read_keylist_snapshot
    paths, _roots, _artifact_bytes = _task14_installed_keylist(tmp_path)
    real_open = keys.os.open

    def denied(path, *args, **kwargs):
        if os.fspath(path) == paths.keylist_current:
            raise PermissionError("injected unreadable artifact")
        return real_open(path, *args, **kwargs)

    monkeypatch.setattr(keys.os, "open", denied)
    with pytest.raises(keys.InstructionKeyError):
        read(paths)
