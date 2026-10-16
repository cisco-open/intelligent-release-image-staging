# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0
"""Durable revocation, issuance races, snapshots and hostile stored state."""
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import threading
import time
from types import SimpleNamespace

import pytest
import catalog
import peer_tls_issuer
import peer_tls_revocations as revocations
import peer_tls_settings
import secrets_store


@pytest.fixture
def ledger(tmp_path, monkeypatch):
    monkeypatch.setenv("IRIS_CONFIG", str(tmp_path / "config"))
    monkeypatch.setenv("IRIS_RUN", str(tmp_path / "run"))
    monkeypatch.setenv("IRIS_PEER_TLS_MODE", "required")
    return revocations.Ledger()


def revoke(ledger, device="edge-1", *, revision=None, request_id=None):
    status = ledger.status(device)
    return ledger.revoke(device, expected_revision=status["revision"] if revision is None else revision,
                         expected_identity_sha256=status["identity_sha256"],
                         request_id=request_id or "00000000-0000-0000-0000-000000000001",
                         actor="console:operator", now=100)


def test_withdrawal_is_durable_idempotent_and_identity_bound(ledger):
    before = ledger.status("edge-1")
    assert before["state"] == "active" and before["revision"] == 0
    assert before["identity_sha256"] == hashlib.sha256(b"edge-1").hexdigest()
    result = revoke(ledger)
    assert result["applied"] is True and result["state"] == "revoked" and result["revision"] == 1
    again = revoke(revocations.Ledger(), revision=0)
    assert again == dict(result, applied=False)
    for path in (ledger.path, ledger.marker, ledger.directory / "revocations.lock"):
        assert path.stat().st_mode & 0o777 == 0o600
    with pytest.raises(revocations.RevisionConflict):
        revoke(ledger, revision=1)
    with pytest.raises(revocations.RevisionConflict):
        revoke(ledger, revision=1, request_id="00000000-0000-0000-0000-000000000009")
    with pytest.raises(revocations.RevisionConflict):
        revoke(ledger, "edge-2")
    with pytest.raises(revocations.RevisionConflict):
        ledger.revoke("edge-1", expected_revision=0, expected_identity_sha256="f" * 64,
                      request_id="00000000-0000-0000-0000-000000000001", actor="operator")


@pytest.mark.parametrize("identity", ["", "seeder", revocations.ORIGIN, "edge\n1", "x" * 129])
def test_service_and_invalid_device_ids_cannot_be_withdrawn(ledger, identity):
    with pytest.raises(ValueError):
        ledger.status(identity)


def test_revisions_are_strict_and_request_payload_cannot_be_reused(ledger):
    revoke(ledger)
    with pytest.raises(revocations.RevisionConflict):
        revoke(ledger, "edge-2", revision=0, request_id="00000000-0000-0000-0000-000000000002")
    with pytest.raises(ValueError):
        revoke(ledger, revision=True)
    assert ledger.status("edge-2")["state"] == "active"


def test_snapshot_is_exact_bounded_sorted_nonce_challenged_and_five_minutes(ledger):
    nonce = "a" * 32
    assert ledger.snapshot("b" * 64, nonce, now=100) == {
        "schema": 1, "nonce": nonce,
        "snapshot": "IRIS-PEER-REVOCATIONS-1\n" + "b" * 64 + "\n0\n100\n400\n"}
    revoke(ledger)
    revoke(ledger, "edge-2", request_id="00000000-0000-0000-0000-000000000002")
    lines = ledger.snapshot("b" * 64, nonce, now=101)["snapshot"].splitlines()
    assert lines[:5] == ["IRIS-PEER-REVOCATIONS-1", "b" * 64, "2", "101", "401"]
    assert lines[5:] == sorted([revocations.device_identity("edge-1"), revocations.device_identity("edge-2")])
    with pytest.raises(ValueError):
        ledger.snapshot("b" * 64, "A" * 32)


@pytest.mark.parametrize("fault", ["missing", "json", "duplicate", "symlink", "mode", "authority"])
def test_lost_corrupt_or_unsafe_established_state_fails_closed(ledger, tmp_path, fault):
    revoke(ledger)
    if fault == "missing":
        ledger.path.unlink()
    elif fault == "json":
        ledger.path.write_text("{broken")
    elif fault == "duplicate":
        ledger.path.write_text('{"revision":0,"revision":1}')
    elif fault == "symlink":
        copy = tmp_path / "copy.json"
        ledger.path.rename(copy)
        ledger.path.symlink_to(copy)
    elif fault == "mode":
        ledger.path.chmod(0o644)
    else:
        ledger.marker.write_text(json.dumps({"schema": 1, "authority": "0" * 32}))
    with pytest.raises(revocations.RevocationError):
        ledger.status("edge-1")
    with pytest.raises(revocations.RevocationError):
        ledger.snapshot("b" * 64, "a" * 32)


def test_interrupted_marker_publication_keeps_existing_revocations(ledger):
    revoke(ledger)
    ledger.marker.unlink()
    assert revocations.Ledger().status("edge-1")["state"] == "revoked"


def test_unknown_write_outcome_is_reconciled_from_durable_state(ledger, monkeypatch):
    ledger.initialize()
    write = peer_tls_settings.atomic_json
    def interrupted(path, data):
        write(path, data)
        raise OSError("simulated response loss after atomic publication")
    monkeypatch.setattr(peer_tls_settings, "atomic_json", interrupted)
    with pytest.raises(revocations.RevocationError):
        revoke(ledger)
    monkeypatch.setattr(peer_tls_settings, "atomic_json", write)
    assert ledger.status("edge-1")["state"] == "revoked"


def test_capacity_refuses_without_discarding_revocations(ledger, monkeypatch):
    monkeypatch.setattr(revocations, "MAX_IDENTITIES", 1)
    revoke(ledger)
    with pytest.raises(revocations.RevocationError, match="limit"):
        revoke(ledger, "edge-2", request_id="00000000-0000-0000-0000-000000000002")
    assert ledger.status("edge-1")["state"] == "revoked"
    assert ledger.status("edge-2")["state"] == "active"


@pytest.fixture
def issuer(ledger, tmp_path, monkeypatch):
    key = tmp_path / "age.key"
    subprocess.run(["age-keygen", "-o", str(key)], check=True, capture_output=True)
    recipient = subprocess.check_output(["age-keygen", "-y", str(key)]).decode().strip()
    monkeypatch.setenv("IRIS_AGE_KEY_FILE", str(key))
    monkeypatch.setenv("IRIS_AGE_RECIPIENTS", recipient)
    csr = subprocess.check_output(["openssl", "req", "-new", "-newkey", "ec",
        "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes", "-subj", "/CN=ignored",
        "-keyout", str(tmp_path / "node.key")], stderr=subprocess.DEVNULL).decode()
    return peer_tls_issuer.Issuer(), csr


def test_issued_certificate_then_withdrawal_blocks_renewal_and_survives_restart(ledger, issuer):
    instance, csr = issuer
    issued = instance.issue("edge-1", csr)
    assert "BEGIN CERTIFICATE" in issued["certificate"]
    revoke(ledger)
    with pytest.raises(peer_tls_issuer.CertificateRevoked):
        peer_tls_issuer.Issuer().issue("edge-1", csr)
    other = instance.issue("edge-2", csr)
    assert "BEGIN CERTIFICATE" in other["certificate"]
    snapshot = instance.revocation_snapshot("a" * 32)
    ca_der = subprocess.check_output(["openssl", "x509", "-outform", "DER"], input=issued["ca"].encode())
    assert snapshot["snapshot"].splitlines()[1] == hashlib.sha256(ca_der).hexdigest()


def test_issuance_and_withdrawal_are_serialized(ledger, issuer, monkeypatch):
    instance, csr = issuer
    entered, release, revoked = threading.Event(), threading.Event(), threading.Event()
    errors = []
    def sign(*args):
        entered.set()
        assert release.wait(5)
        return {"certificate": "issued-before-withdrawal"}
    monkeypatch.setattr(instance, "_issue_identity", sign)
    def issue():
        try:
            instance.issue("edge-1", csr)
        except Exception as exc:
            errors.append(exc)
    def withdraw():
        try:
            revoke(ledger)
            revoked.set()
        except Exception as exc:
            errors.append(exc)
    issuing = threading.Thread(target=issue)
    issuing.start()
    assert entered.wait(5)
    withdrawing = threading.Thread(target=withdraw)
    withdrawing.start()
    assert not revoked.wait(.05)
    release.set()
    issuing.join(5); withdrawing.join(5)
    assert not errors and revoked.is_set()
    with pytest.raises(peer_tls_issuer.CertificateRevoked):
        instance.issue("edge-1", csr)


def test_managed_restore_cannot_roll_back_revocations(ledger, tmp_path):
    sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools"))
    from iris_installer import restore
    from iris_installer.state import InstallError
    ledger.initialize()
    archived = tmp_path / "archived"
    shutil.copytree(ledger.directory.parent, archived)
    revoke(ledger)
    install = SimpleNamespace(base=tmp_path)
    with pytest.raises(InstallError, match="different credential generation"):
        restore._config_generation(install, ledger.directory.parent, archived, tmp_path / "identity")


def test_heartbeat_preserves_only_strict_native_observation():
    report = {"supported": True, "mode": "required", "state": "valid", "authority": "a" * 64,
              "revision": 1, "issued_at": 100, "expires_at": 400, "own_revoked": False, "observed_at": 110}
    value = {"configured_mode": "required", "runtime_mode": "required", "runtime_source": "aria2_rpc",
             "revocations": report}
    assert catalog._hb_peer_tls(value)["revocations"] == report
    for changes in ({"revision": True}, {"expires_at": 401}, {"authority": None},
                    {"supported": False}, {"state": "applied"}, {"private": "discard"}):
        value["revocations"] = dict(report, **changes)
        assert "revocations" not in catalog._hb_peer_tls(value)


def approve(ledger, *, request_id="00000000-0000-0000-0000-000000000002", revision=1):
    return ledger.prepare_reenrollment("edge-1", expected_revision=revision,
        expected_identity_sha256=revocations.device_identity("edge-1"), request_id=request_id,
        actor="console:operator", now=110)


def test_recovery_approval_retains_denial_until_explicit_fresh_enrollment(ledger, issuer):
    instance, csr = issuer
    old = instance.issue("edge-1", csr)["identity_sha256"]
    revoke(ledger)
    approval = approve(ledger)
    assert approval["state"] == "reenrollment-required"
    assert approval["identity_sha256"] == old and approval["revision"] == 2
    assert approve(ledger) == dict(approval, applied=False)
    with pytest.raises(peer_tls_issuer.CertificateRevoked):
        instance.issue("edge-1", csr)
    with ledger.locked() as data:
        assert ledger._activate_enrollment(data, "edge-1", now=120) is True
    result = ledger.status("edge-1")
    assert result["state"] == "active" and result["revision"] == 3
    assert result["identity_sha256"] != old
    assert result["recovery_request_id"] == approval["recovery_request_id"]
    assert result["request_id"] is None and result["revoked_at"] is None
    assert approve(ledger) == dict(result, applied=False)
    certificate = instance.issue("edge-1", csr)
    assert certificate["identity_sha256"] == result["identity_sha256"]
    assert old in instance.revocation_snapshot("a" * 32)["snapshot"]
    assert result["identity_sha256"] not in instance.revocation_snapshot("a" * 32)["snapshot"]
    with pytest.raises(revocations.RevisionConflict):
        ledger.revoke("edge-1", expected_revision=3, expected_identity_sha256=old,
                      request_id="00000000-0000-0000-0000-000000000009", actor="operator")


def test_repeated_recovery_never_removes_older_certificate_tombstones(ledger):
    old = revocations.device_identity("edge-1")
    revoke(ledger)
    approve(ledger)
    with ledger.locked() as data:
        ledger._activate_enrollment(data, "edge-1", now=120)
    middle = ledger.status("edge-1")["identity_sha256"]
    revoke(ledger, request_id="00000000-0000-0000-0000-000000000003")
    assert ledger.status("edge-1")["recovery_request_id"] is None
    ledger.prepare_reenrollment("edge-1", expected_revision=4, expected_identity_sha256=middle,
        request_id="00000000-0000-0000-0000-000000000004", actor="operator", now=130)
    with ledger.locked() as data:
        ledger._activate_enrollment(data, "edge-1", now=140)
    latest = ledger.status("edge-1")["identity_sha256"]
    snapshot = ledger.snapshot("a" * 64, "b" * 32, now=150)["snapshot"]
    assert old in snapshot and middle in snapshot and latest not in snapshot
    assert ledger.status("edge-1")["revision"] == 6


def test_ordinary_bearer_refresh_cannot_activate_recovery(ledger, tmp_path, monkeypatch):
    path = tmp_path / "secrets.json"
    monkeypatch.setenv("IRIS_AGE_RECIPIENTS", "")
    monkeypatch.setenv("IRIS_SECRETS_ENC", str(tmp_path / "config/secrets.json.age"))
    store = secrets_store.load(str(path))
    token = secrets_store.mint(store, "edge-1", "catalog_token", time.time())
    secrets_store.save(store, str(path))
    revoke(ledger)
    approve(ledger)
    service = catalog.Catalog(catalog.CatalogStore(str(tmp_path / "state")), str(path),
                              audit_path=str(tmp_path / "audit.jsonl"))
    result = service._handle_token_refresh("edge-1", token=token)
    assert result[0] == 200
    assert ledger.status("edge-1")["state"] == "reenrollment-required"


def test_recovery_request_cannot_reuse_another_operation_or_bypass_review(ledger):
    revoke(ledger)
    with pytest.raises(revocations.RevisionConflict):
        approve(ledger, request_id="00000000-0000-0000-0000-000000000001")
    with pytest.raises(revocations.RevisionConflict):
        approve(ledger, revision=0)
    approve(ledger)
    with pytest.raises(revocations.RevisionConflict):
        approve(ledger, revision=2)
    with pytest.raises(revocations.RevisionConflict):
        revoke(ledger, "edge-2", request_id="00000000-0000-0000-0000-000000000002")
    assert ledger.status("edge-2")["state"] == "active"


def test_explicit_minter_replaces_old_bearers_before_activating_recovery(ledger, tmp_path, monkeypatch, capsys):
    from test_iris_mint_enrollment import _load_cli
    path = tmp_path / "secrets.json"
    monkeypatch.setenv("IRIS_SECRETS", str(path))
    monkeypatch.setenv("IRIS_STATE", str(tmp_path / "state"))
    monkeypatch.setenv("IRIS_AGE_RECIPIENTS", "")
    monkeypatch.setenv("IRIS_SECRETS_ENC", str(tmp_path / "config/secrets.json.age"))
    store = secrets_store.load(str(path))
    old_token = secrets_store.mint(store, "edge-1", "catalog_token", 100)
    store["devices"]["edge-1"]["catalog_token_prev"] = dict(
        store["devices"]["edge-1"]["catalog_token"], value="old-test-previous-bearer")
    secrets_store.save(store, str(path))
    revoke(ledger)
    cli = _load_cli()
    # A normal mint does not itself grant recovery approval.
    assert cli.main(["edge-1"]) == 0
    capsys.readouterr()
    assert ledger.status("edge-1")["state"] == "revoked"
    approval = approve(ledger)
    current_before = secrets_store.load(str(path))["devices"]["edge-1"]["catalog_token"]["value"]
    activate = revocations.Ledger._activate_enrollment
    observed = []
    def check_order(self, data, device_id, now=None):
        credentials = secrets_store.load(str(path))["devices"][device_id]
        observed.append(credentials["catalog_token"]["value"])
        assert credentials["catalog_token"]["value"] not in (old_token, current_before)
        assert "catalog_token_prev" not in credentials
        return activate(self, data, device_id, now)
    monkeypatch.setattr(revocations.Ledger, "_activate_enrollment", check_order)
    assert cli.main(["edge-1"]) == 0
    token = capsys.readouterr().out.strip()
    assert token == observed[-1]
    assert ledger.status("edge-1")["state"] == "active"
    assert ledger.status("edge-1")["recovery_request_id"] == approval["recovery_request_id"]


def test_failed_mint_never_activates_or_delivers_pending_identity(ledger, tmp_path, monkeypatch, capsys):
    from test_iris_mint_enrollment import _load_cli
    monkeypatch.setenv("IRIS_SECRETS", str(tmp_path / "secrets.json"))
    monkeypatch.setenv("IRIS_STATE", str(tmp_path / "state"))
    monkeypatch.setenv("IRIS_AGE_RECIPIENTS", "")
    revoke(ledger)
    approve(ledger)
    cli = _load_cli()
    def fail(*args, **kwargs):
        raise OSError("simulated persist failure")
    monkeypatch.setattr(cli.secretfs, "persist_store", fail)
    assert cli.main(["edge-1"]) == 1
    assert capsys.readouterr().out == ""
    assert ledger.status("edge-1")["state"] == "reenrollment-required"


def test_lost_recovery_activation_response_is_safe_to_retry(ledger, tmp_path, monkeypatch, capsys):
    from test_iris_mint_enrollment import _load_cli
    monkeypatch.setenv("IRIS_SECRETS", str(tmp_path / "secrets.json"))
    monkeypatch.setenv("IRIS_STATE", str(tmp_path / "state"))
    monkeypatch.setenv("IRIS_AGE_RECIPIENTS", "")
    revoke(ledger)
    approve(ledger)
    cli = _load_cli()
    save = revocations.Ledger._save
    def interrupted(self, data):
        save(self, data)
        raise OSError("simulated activation reply loss")
    monkeypatch.setattr(revocations.Ledger, "_save", interrupted)
    assert cli.main(["edge-1"]) == 1
    assert capsys.readouterr().out == ""
    assert ledger.status("edge-1")["state"] == "active"
    activated = ledger.status("edge-1")["identity_sha256"]
    monkeypatch.setattr(revocations.Ledger, "_save", save)
    assert cli.main(["edge-1"]) == 0
    assert len(capsys.readouterr().out.strip()) == 32
    assert ledger.status("edge-1")["identity_sha256"] == activated
