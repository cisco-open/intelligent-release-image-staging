# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Recoverable same-key certificate renewal for the Kubernetes worker channel.

The CA and both leaf private keys stay in their original host custody. Only
public certificates are renewed. An old/new client-certificate overlap remains
until a request from the restarted, owned server proves the new TLS identity.
"""

import base64
import copy
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import ssl
import tempfile
import time
import uuid

from .lifecycle_network import _private, endpoint
from .backup_archive import private_directory
from .state import InstallError, Journal, atomic_write, regular_bytes

ROLES = ("ca", "worker", "client")
TERMINAL = "complete"


def _id(value):
    try:
        if not isinstance(value, str) or str(uuid.UUID(value)) != value:
            raise ValueError()
    except (ValueError, TypeError, AttributeError):
        raise InstallError("Choose a canonical certificate-renewal operation ID") from None
    return value


def _sha(value):
    return hashlib.sha256(value).hexdigest()


def _cert_sha(path):
    return _sha(ssl.PEM_cert_to_DER_cert(regular_bytes(path, 16384).decode()))


def load_custody(base, url, runner, *, allow_expired=True):
    """Validate existing keys and certificate chains without regenerating them.

    Expired certificates may load solely so the root-only Unix recovery UI can
    renew them. Normal TLS clients still perform their own expiry validation.
    """
    host, _port = endpoint(url)
    directory = Path(base) / "lifecycle-tls"
    info = directory.lstat()
    import stat
    if (directory.resolve() != directory or not stat.S_ISDIR(info.st_mode)
            or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700):
        raise InstallError("Lifecycle certificate custody is unsafe")
    names = {role + suffix for role in ROLES for suffix in (".key", ".crt")}
    if set(p.name for p in directory.iterdir()) != names | {"endpoint.json"}:
        raise InstallError("Lifecycle certificate custody is incomplete")
    if json.loads(regular_bytes(directory / "endpoint.json")) != {"url": url}:
        raise InstallError("Lifecycle certificate endpoint differs from the installation")
    custody = {name: directory / name for name in names}
    for role in ROLES:
        _private(custody[role + ".key"])
        public = runner(["openssl", "pkey", "-in", custody[role + ".key"], "-pubout"], capture=True)
        actual = runner(["openssl", "x509", "-in", custody[role + ".crt"], "-pubkey", "-noout"], capture=True)
        if public != actual:
            raise InstallError("Lifecycle certificate and private key no longer match")
    for role, purpose in (("worker", "sslserver"), ("client", "sslclient")):
        identity = []
        if role == "worker":
            try:
                ipaddress.ip_address(host)
                identity = ["-verify_ip", host]
            except ValueError:
                identity = ["-verify_hostname", host]
        runner(["openssl", "verify", *( ["-no_check_time"] if allow_expired else []),
                "-CAfile", custody["ca.crt"], "-purpose", purpose, *identity, custody[role + ".crt"]])
    return custody


def status(base, url, runner):
    custody = load_custody(base, url, runner)
    now = int(time.time())
    certificates = []
    for role in ROLES:
        expiry = runner(["openssl", "x509", "-in", custody[role + ".crt"], "-enddate", "-noout"], capture=True).decode().strip()
        if not expiry.startswith("notAfter="):
            raise InstallError("Cannot read lifecycle certificate expiry")
        expires_at = int(ssl.cert_time_to_seconds(expiry[len("notAfter="):]))
        certificates.append({"name": role, "expires_at": expires_at, "days_remaining": (expires_at - now) // 86400,
                             "certificate_sha256": _cert_sha(custody[role + ".crt"])})
    pointer = Path(base) / "lifecycle-transport-operation.json"
    if pointer.exists() or pointer.is_symlink():
        _private(pointer)
    pending = json.loads(regular_bytes(pointer)) if pointer.exists() else None
    return {"available": True, "mode": "same-key-certificate-renewal", "certificates": certificates,
            "renewal_due": any(c["days_remaining"] <= 30 for c in certificates),
            "pending": ({"request_id": pending["request_id"], "phase": pending["phase"]}
                        if pending and pending["phase"] != TERMINAL else None)}


def _save(base, directory, record, phase):
    record["phase"] = phase
    value = json.dumps(record, sort_keys=True).encode()
    atomic_write(directory / "record.json", value)
    atomic_write(Path(base) / "lifecycle-transport-operation.json", value)


def _candidate_custody(custody, directory):
    return {name: directory / name if name.endswith(".crt") else path for name, path in custody.items()}


def _key_proof(custody, runner):
    return {role: _sha(runner(["openssl", "pkey", "-in", custody[role + ".key"], "-pubout", "-outform", "DER"], capture=True)) for role in ROLES}


def _prepare(base, directory, record, custody, url, runner):
    host, _port = endpoint(url)
    if any(_cert_sha(directory / ("old-" + role + ".crt")) != record["before"][role] for role in ROLES):
        raise InstallError("Original connection certificate custody changed")
    # Re-sign the CA certificate with its existing key. This preserves subject,
    # public key and CA constraints while giving it a new serial and validity.
    runner(["openssl", "x509", "-in", directory / "old-ca.crt", "-signkey", custody["ca.key"],
            "-days", "1095", "-set_serial", "0x" + secrets.token_hex(16), "-out", directory / "ca.crt"])
    for role, purpose in (("worker", "serverAuth"), ("client", "clientAuth")):
        runner(["openssl", "x509", "-x509toreq", "-in", directory / ("old-" + role + ".crt"),
                "-signkey", custody[role + ".key"], "-out", directory / (role + ".csr")])
        extension = "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=" + purpose + "\n"
        if role == "worker":
            try:
                ipaddress.ip_address(host)
                san = "IP:" + host
            except ValueError:
                san = "DNS:" + host
            extension += "subjectAltName=" + san + "\n"
        extension_path = directory / (role + ".extensions")
        atomic_write(extension_path, extension.encode())
        runner(["openssl", "x509", "-req", "-in", directory / (role + ".csr"), "-CA", directory / "ca.crt",
                "-CAkey", custody["ca.key"], "-set_serial", "0x" + secrets.token_hex(16), "-days", "397",
                "-extfile", extension_path, "-out", directory / (role + ".crt")])
    candidate = _candidate_custody(custody, directory)
    _validate_candidate(candidate, record["key_spki_sha256"], url, runner)
    record["after"] = {role: _cert_sha(candidate[role + ".crt"]) for role in ROLES}
    _save(base, directory, record, "prepared")


def _validate_candidate(custody, keys, url, runner, *, check_expiry=True):
    if _key_proof(custody, runner) != keys:
        raise InstallError("Lifecycle renewal private-key identity changed")
    host, _port = endpoint(url)
    for role in ROLES:
        public = runner(["openssl", "x509", "-in", custody[role + ".crt"], "-pubkey", "-noout"], capture=True)
        expected = runner(["openssl", "pkey", "-in", custody[role + ".key"], "-pubout"], capture=True)
        if public != expected:
            raise InstallError("Renewed lifecycle certificate changed its public key")
        if check_expiry:
            runner(["openssl", "x509", "-in", custody[role + ".crt"], "-checkend", "604800", "-noout"])
    for role, purpose in (("worker", "sslserver"), ("client", "sslclient")):
        identity = []
        if role == "worker":
            try:
                ipaddress.ip_address(host)
                identity = ["-verify_ip", host]
            except ValueError:
                identity = ["-verify_hostname", host]
        runner(["openssl", "verify", *([] if check_expiry else ["-no_check_time"]), "-CAfile", custody["ca.crt"], "-purpose", purpose,
                *identity, custody[role + ".crt"]])


def _overlap(record):
    return tuple(bytes.fromhex(value) for value in dict.fromkeys(
        [record["before"]["client"], *[item["client"] for item in record.get("certificate_history", [])]]))


def _allowed(record, role):
    return {record["before"][role], record["after"][role], *[item[role] for item in record.get("certificate_history", [])]}


def _expiring(custody, runner):
    for role in ROLES:
        expiry = runner(["openssl", "x509", "-in", custody[role + ".crt"], "-enddate", "-noout"], capture=True).decode().strip()
        if not expiry.startswith("notAfter="):
            raise InstallError("Cannot establish candidate certificate expiry")
        if ssl.cert_time_to_seconds(expiry[len("notAfter="):]) <= time.time() + 7 * 86400:
            return True
    return False


def startup_custody(base, url, runner):
    """Restore an already approved overlap in memory, never publish new files."""
    custody = load_custody(base, url, runner)
    pointer = Path(base) / "lifecycle-transport-operation.json"
    if not pointer.exists():
        return custody, ()
    _private(pointer)
    record = json.loads(regular_bytes(pointer))
    if record["phase"] in ("preparing", "renewing-expired", TERMINAL):
        return custody, ()
    directory = Path(base) / "lifecycle-transport-operations" / _id(record["request_id"])
    private_directory(directory)
    candidate = _candidate_custody(custody, directory)
    _validate_candidate(candidate, record["key_spki_sha256"], url, runner, check_expiry=False)
    if any(_cert_sha(candidate[role + ".crt"]) != record["after"][role] for role in ROLES):
        raise InstallError("Approved lifecycle certificate candidate changed")
    return candidate, _overlap(record)


def proof_request(base, request, peer_sha256):
    if not isinstance(request, dict) or set(request) != {"action", "request_id"} or request["action"] != "transport-proof":
        raise InstallError("Invalid connection proof request")
    identifier = _id(request["request_id"])
    pointer = Path(base) / "lifecycle-transport-operation.json"
    _private(pointer)
    record = json.loads(regular_bytes(pointer))
    if record.get("request_id") != identifier or record.get("after", {}).get("client") != peer_sha256:
        raise InstallError("Connection proof does not match the renewed client")
    return {"request_id": identifier, "client_sha256": peer_sha256}


_PROBE = '''import os,json,ssl,http.client,hashlib,sys
from urllib.parse import urlsplit
u=urlsplit(os.environ['IRIS_LIFECYCLE_URL'])
c=ssl.create_default_context(cafile=os.environ['IRIS_LIFECYCLE_CA'])
c.load_cert_chain(os.environ['IRIS_LIFECYCLE_CERT'],os.environ['IRIS_LIFECYCLE_KEY'])
h=http.client.HTTPSConnection(u.hostname,u.port,context=c,timeout=15)
h.connect(); fingerprint=hashlib.sha256(h.sock.getpeercert(binary_form=True)).hexdigest()
h.request('POST','/v1/lifecycle',body=json.dumps({'action':'transport-proof','request_id':sys.argv[1]}).encode(),headers={'Content-Type':'application/json'})
r=h.getresponse(); result=json.loads(r.read(4097)); h.close()
if r.status!=200 or result.get('ok') is not True: raise RuntimeError('proof refused')
result=result['result']; result['worker_sha256']=fingerprint; print(json.dumps(result))
'''


def renew(base, request_id, network_server, *, recovery=False):
    identifier = _id(request_id)
    base = Path(base)
    with Journal(base).locked() as journal:
        if not journal.document or journal.document["config"].get("target") != "kubernetes":
            raise InstallError("Connection certificate renewal is available for installer-owned Kubernetes deployments")
        from .deploy import installation
        install = installation(journal)
        url = install.config["lifecycle_url"]
        custody = load_custody(base, url, install.command)
        directory = base / "lifecycle-transport-operations" / identifier
        pointer = base / "lifecycle-transport-operation.json"
        if pointer.exists() or pointer.is_symlink():
            _private(pointer)
        prior = json.loads(regular_bytes(pointer)) if pointer.exists() else None
        if prior and prior.get("instance_id") != journal.document["id"]:
            raise InstallError("Connection renewal belongs to a different installation")
        if prior and prior.get("phase") != TERMINAL and prior.get("request_id") != identifier:
            raise InstallError("Recover the existing connection certificate renewal first")
        if directory.exists():
            private_directory(directory)
            _private(directory / "record.json")
            record = json.loads(regular_bytes(directory / "record.json"))
            if record.get("instance_id") != journal.document["id"] or record.get("request_id") != identifier:
                raise InstallError("Connection renewal authority changed")
            if record["phase"] == TERMINAL:
                if any(_cert_sha(custody[role + ".crt"]) != record["after"][role] for role in ROLES):
                    raise InstallError("Completed connection certificates changed")
                network_server.configure_transport(custody)
                _save(base, directory, record, TERMINAL)
                return record["proof"]
            if not recovery:
                raise InstallError("Use same-operation recovery for interrupted connection renewal")
            install._recover_object_update()
        else:
            pending_update = base / "kube-update.json"
            if pending_update.exists() or pending_update.is_symlink():
                raise InstallError("Recover the existing Kubernetes update under its original operation before connection renewal")
            if recovery:
                jobs_path = base / "lifecycle-jobs.json"
                if not jobs_path.exists() and not jobs_path.is_symlink():
                    raise InstallError("There is no admitted connection renewal to recover")
                _private(jobs_path)
                admitted = json.loads(regular_bytes(jobs_path))
                if not any(job.get("id") == identifier and job.get("action") == "renew-transport"
                           and job.get("state") in ("running", "recovery-required") for job in admitted):
                    raise InstallError("There is no admitted connection renewal to recover")
            install.pin_runtime()
            directory.parent.mkdir(mode=0o700, exist_ok=True)
            private_directory(directory.parent)
            record = {"schema": 1, "request_id": identifier, "instance_id": journal.document["id"],
                      "before": {role: _cert_sha(custody[role + ".crt"]) for role in ROLES},
                      "key_spki_sha256": _key_proof(custody, install.command), "phase": "preparing"}
            with tempfile.TemporaryDirectory(prefix=".preparing-", dir=directory.parent) as scratch:
                ready = Path(scratch) / "ready"
                ready.mkdir(mode=0o700)
                for role in ROLES:
                    atomic_write(ready / ("old-" + role + ".crt"), regular_bytes(custody[role + ".crt"], 16384), 0o644)
                atomic_write(ready / "record.json", json.dumps(record, sort_keys=True).encode())
                os.rename(ready, directory)
                fd = os.open(directory.parent, os.O_RDONLY | os.O_DIRECTORY)
                try:
                    os.fsync(fd)
                finally:
                    os.close(fd)
            _save(base, directory, record, "preparing")
        if record["phase"] in ("preparing", "renewing-expired"):
            _prepare(base, directory, record, custody, url, install.command)
        candidate = _candidate_custody(custody, directory)
        _validate_candidate(candidate, record["key_spki_sha256"], url, install.command, check_expiry=False)
        if any(_cert_sha(candidate[role + ".crt"]) != record["after"][role] for role in ROLES):
            raise InstallError("Approved lifecycle certificate candidate changed")
        if any(_cert_sha(custody[role + ".crt"]) not in _allowed(record, role) for role in ROLES):
            raise InstallError("Lifecycle certificate changed outside the approved renewal")
        if _expiring(candidate, install.command):
            if not recovery:
                raise InstallError("Recover this operation to renew its expired pending certificates")
            history = record.setdefault("certificate_history", [])
            if len(history) >= 10:
                raise InstallError("Connection renewal revision limit reached; preserve its authority for review")
            for role in ROLES:
                atomic_write(directory / ("previous-" + str(len(history)) + "-" + role + ".crt"), regular_bytes(candidate[role + ".crt"], 16384), 0o644)
            history.append(dict(record["after"]))
            _save(base, directory, record, "renewing-expired")
            _prepare(base, directory, record, custody, url, install.command)
        _validate_candidate(candidate, record["key_spki_sha256"], url, install.command)
        install.pin_runtime()
        network_server.configure_transport(candidate, extra_client_digests=_overlap(record))
        _save(base, directory, record, "overlap-active")
        secret = copy.deepcopy(next(o for o in install.manifests() if o["kind"] == "Secret" and o["metadata"]["name"] == "iris-lifecycle"))
        approved = {name: base64.b64encode(regular_bytes(candidate[name], 16384)).decode() for name in ("ca.crt", "client.crt", "client.key")}
        if secret["data"] != approved:
            secret["data"] = approved
            install._replace_owned(secret)
        _save(base, directory, record, "secret-published")
        deployment = copy.deepcopy(next(o for o in install.manifests() if o["kind"] == "Deployment" and o["metadata"]["name"] == "iris-seed-server"))
        annotations = deployment["spec"]["template"]["metadata"].setdefault("annotations", {})
        generation = identifier + ":" + record["after"]["client"]
        if annotations.get("iris.cisco.com/lifecycle-renewal") != generation:
            annotations["iris.cisco.com/lifecycle-renewal"] = generation
            install._replace_owned(deployment)
        install.kube("rollout", "status", "deployment/iris-seed-server", "--timeout=300s", timeout=330)
        _save(base, directory, record, "server-restarted")
        server_pods = install._pods("iris")
        proof = json.loads(install.execute("python3", "-I", "-B", "-c", _PROBE, identifier, capture=True, timeout=30))
        expected = {"request_id": identifier, "client_sha256": record["after"]["client"], "worker_sha256": record["after"]["worker"]}
        if proof != expected or install._pods("iris") != server_pods:
            raise InstallError("Restarted server did not prove the renewed connection certificates")
        _save(base, directory, record, "new-client-verified")
        for role in ROLES:
            current = _cert_sha(custody[role + ".crt"])
            if current not in _allowed(record, role):
                raise InstallError("Lifecycle certificate changed outside the approved renewal")
            atomic_write(custody[role + ".crt"], regular_bytes(candidate[role + ".crt"], 16384), 0o644)
        _save(base, directory, record, "certificates-published")
        network_server.configure_transport(custody)
        if (install._pods("iris") != server_pods
                or json.loads(install.execute("python3", "-I", "-B", "-c", _PROBE, identifier, capture=True, timeout=30)) != expected
                or install._pods("iris") != server_pods):
            raise InstallError("Renewed connection proof failed after retiring the old client certificate")
        if _key_proof(custody, install.command) != record["key_spki_sha256"]:
            raise InstallError("Connection renewal unexpectedly changed private-key identities")
        record["proof"] = dict(expected, ca_sha256=record["after"]["ca"], same_private_keys=True, old_client_retired=True,
                               server_pod_uid=server_pods[0]["uid"])
        _save(base, directory, record, TERMINAL)
        return record["proof"]
