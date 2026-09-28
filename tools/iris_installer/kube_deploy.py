# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Explicit-cluster installation with private server storage and fenced resources.

The installer owns a new namespace, never adopts an existing one, and builds on
the Ubuntu controller. Registry publication is the normal image transport. The
explicit k3s transport is restricted to a local, single-node lab cluster.
"""

import base64
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import socket
import ssl
import stat
import tarfile
import uuid

from .deploy import DockerInstall, OWNER_CLAIM, PRODUCTION_REVIEW, WAITING_APPROVAL, digest, run
from .state import InstallError, atomic_write, regular_bytes


COMMON = {"target", "instance", "host", "console_bind", "console_port", "recovery_recipient", "peer_tls"}
FIELDS = {"kubeconfig_path", "kube_context", "kube_namespace", "kube_storage_class",
          "kube_storage_size", "kube_registry", "kube_registry_auth", "kube_console_replicas", "kube_image_import", "kube_node", "lifecycle_url"}
LABEL = "iris.cisco.com/installation"
INTENT = "iris.cisco.com/intent-sha256"
SERVICES = {"iris": "iris-seed-server", "console": "iris-console"}


def validate_config(config):
    from .deploy import validate_config as docker_validate
    if not isinstance(config, dict) or set(config) != COMMON | FIELDS or config.get("target") != "kubernetes":
        raise InstallError("Kubernetes installation configuration is incomplete")
    docker_validate(dict({k: config[k] for k in COMMON}, target="docker"))
    from .lifecycle_network import endpoint
    endpoint(config["lifecycle_url"])
    if (not isinstance(config["kubeconfig_path"], str)
            or not Path(config["kubeconfig_path"]).is_absolute()
            or Path(config["kubeconfig_path"]).resolve() != Path(config["kubeconfig_path"])):
        raise InstallError("Supply an absolute, non-symlink kubeconfig path")
    if not isinstance(config["kube_context"], str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:@/-]{0,159}", config["kube_context"]):
        raise InstallError("Supply an explicit Kubernetes context")
    for field in ("kube_namespace", "kube_storage_class"):
        value = config[field]
        if not isinstance(value, str) or not re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]{0,61}[a-z0-9])?", value):
            raise InstallError("Supply a concrete Kubernetes namespace and storage class")
    if config["kube_namespace"] in ("default", "kube-system", "kube-public", "kube-node-lease"):
        raise InstallError("Use a new dedicated IRIS namespace")
    if not isinstance(config["kube_storage_size"], str) or not re.fullmatch(r"[1-9][0-9]{0,4}(?:Gi|Ti)", config["kube_storage_size"]):
        raise InstallError("Storage size must be a positive Gi or Ti quantity")
    if type(config["kube_console_replicas"]) is not int or not 1 <= config["kube_console_replicas"] <= 8:
        raise InstallError("Console replicas must be between one and eight; the stateful server remains one replica")
    if config["kube_image_import"] not in ("registry", "k3s"):
        raise InstallError("Select registry publication or explicit local k3s image import")
    registry = config["kube_registry"]
    if not isinstance(registry, str) or (registry and not re.fullmatch(r"[a-z0-9][a-z0-9.:-]*(?:/[a-z0-9][a-z0-9._-]*)+", registry)):
        raise InstallError("Registry must be a repository prefix without credentials, URL scheme or tag")
    if config["kube_image_import"] == "registry" and not registry:
        raise InstallError("Registry publication requires an explicit registry repository prefix")
    node = config["kube_node"]
    if not isinstance(node, str) or (node and not re.fullmatch(r"[a-z0-9][a-z0-9.-]{0,252}", node)):
        raise InstallError("Invalid explicit Kubernetes node")
    if config["kube_image_import"] == "k3s" and (not node or registry):
        raise InstallError("Local k3s import requires an explicit node and no registry")
    if config["kube_image_import"] == "registry" and node:
        raise InstallError("Node pinning is reserved for explicit local k3s import")
    auth = config["kube_registry_auth"]
    if not isinstance(auth, str) or (auth and (not Path(auth).is_absolute() or Path(auth).resolve() != Path(auth))):
        raise InstallError("Registry authentication requires an explicit absolute, non-symlink config.json path")
    if config["kube_image_import"] == "k3s" and auth:
        raise InstallError("Local k3s import does not use registry credentials")


def validate_kube_config(config):
    validate_config(config)


def preflight(config, runner=run):
    """Read-only cluster checks before reserving installation state."""
    from types import SimpleNamespace
    document = {"config": config, "id": "preflight", "completed": {}}
    journal = SimpleNamespace(directory=Path("/var/empty/iris-preflight"), document=document,
                              checkpoint=lambda key, value: document["completed"].update({key: value}))
    KubeInstall(journal, runner).cluster_preflight()


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def _archive_identity(archive, source_id, config_digest):
    """Docker classic IDs name configs; containerd-backed IDs name OCI roots."""
    if source_id == config_digest:
        return
    if not re.fullmatch(r'sha256:[0-9a-f]{64}', source_id):
        raise InstallError('Invalid recorded image identity')
    selected = {}
    blob = 'blobs/sha256/' + source_id.split(':', 1)[1]
    with tarfile.open(archive) as stream:
        for count, member in enumerate(stream):
            if count > 8192:
                raise InstallError('Image archive has too many members')
            if member.name not in ('index.json', blob):
                continue
            if not member.isfile() or not 0 < member.size <= 1024 * 1024 or member.name in selected:
                raise InstallError('Invalid image archive identity member')
            selected[member.name] = stream.extractfile(member).read()
    try:
        references = json.loads(selected['index.json'])['manifests']
        if (not any(item.get('digest') == source_id for item in references)
                or 'sha256:' + hashlib.sha256(selected[blob]).hexdigest() != source_id):
            raise ValueError()
    except (KeyError, ValueError, TypeError, AttributeError):
        raise InstallError('Image archive does not contain the recorded immutable build') from None


def _contains(actual, expected):
    """API defaults are allowed; changes to installer-declared fields are not."""
    if isinstance(expected, dict):
        if not isinstance(actual, dict):
            return False
        if expected.get("kind") in ("Secret", "ConfigMap"):
            if any(actual.get(field, {}) != expected.get(field, {}) for field in ("data", "binaryData", "stringData")):
                return False
        if expected.get("kind") in ("Pod", "Deployment"):
            want = expected["spec"] if expected["kind"] == "Pod" else expected["spec"]["template"]["spec"]
            have = actual.get("spec", {}) if expected["kind"] == "Pod" else actual.get("spec", {}).get("template", {}).get("spec", {})
            for field in ("hostNetwork", "hostPID", "hostIPC", "shareProcessNamespace"):
                if have.get(field, False) != want.get(field, False):
                    return False
            if have.get("securityContext", {}) != want.get("securityContext", {}):
                return False
            for category in ("containers", "initContainers", "ephemeralContainers"):
                wanted, actuals = want.get(category, []), have.get(category, [])
                if len(wanted) != len(actuals):
                    return False
                for a, b in zip(actuals, wanted):
                    for field in ("env", "envFrom", "command", "args", "securityContext", "lifecycle"):
                        if a.get(field) != b.get(field):
                            return False
        return isinstance(actual, dict) and all(k in actual and _contains(actual[k], v) for k, v in expected.items())
    if isinstance(expected, list):
        return isinstance(actual, list) and len(actual) == len(expected) and all(_contains(a, b) for a, b in zip(actual, expected))
    return actual == expected


class KubeInstall(DockerInstall):
    def __init__(self, journal, runner=run):
        original = journal.document["config"]
        validate_config(original)
        # Reuse the source/build engine without weakening Docker's config check.
        journal.document["config"] = dict({k: original[k] for k in COMMON}, target="docker")
        try:
            super().__init__(journal, runner)
        finally:
            journal.document["config"] = original
        self.config = original
        self.manifest_file = self.base / "kube.json"

    def kube(self, *args, **kwargs):
        executable = ["kubectl"] if shutil.which("kubectl") else ["k3s", "kubectl"]
        return self.command([*executable, "--kubeconfig", self.config["kubeconfig_path"],
                             "--context", self.config["kube_context"],
                             "--namespace", self.config["kube_namespace"], *args], **kwargs)

    def get(self, kind, name):
        raw = self.kube("get", kind, name, "--ignore-not-found", "-o", "json", capture=True)
        return json.loads(raw) if raw.strip() else None

    def cluster_preflight(self):
        kubeconfig = Path(self.config["kubeconfig_path"])
        info = kubeconfig.lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0
                or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1):
            raise InstallError("Explicit kubeconfig must be root-owned mode 0600 without hard links")
        from . import ubuntu
        ubuntu.validate_kubernetes_versions(json.loads(self.kube("version", "-o", "json", capture=True)))
        context = json.loads(self.kube("config", "view", "--minify", "-o", "json", capture=True))
        clusters = context.get("clusters", [])
        if len(clusters) != 1 or not clusters[0].get("cluster", {}).get("server", "").startswith("https://"):
            raise InstallError("Kubernetes API must use verified HTTPS")
        cluster = clusters[0]["cluster"]
        if cluster.get("insecure-skip-tls-verify"):
            raise InstallError("Kubernetes API TLS verification must remain enabled")
        system = self.get("namespace", "kube-system")
        if not system or not system["metadata"].get("uid"):
            raise InstallError("Cannot establish cluster identity")
        identity = {"uid": system["metadata"]["uid"], "server": cluster["server"],
                    "context": self.config["kube_context"]}
        saved = self.journal.document["completed"].get("kube-cluster")
        if saved and saved != identity:
            raise InstallError("Kubernetes cluster identity changed; no resources were modified")
        if not saved:
            if self.get("namespace", self.config["kube_namespace"]):
                raise InstallError("Namespace already exists; adoption is not supported")
            self.journal.checkpoint("kube-cluster", identity)
        storage = self.get("storageclass", self.config["kube_storage_class"])
        if not storage:
            raise InstallError("The selected StorageClass does not exist")
        if self.config["kube_image_import"] == "k3s":
            nodes = json.loads(self.kube("get", "nodes", "-o", "json", capture=True))["items"]
            local = json.loads(self.command(["ip", "-j", "address", "show"], capture=True))
            addresses = {a["local"] for link in local for a in link.get("addr_info", []) if "local" in a}
            if (len(nodes) != 1 or nodes[0]["metadata"]["name"] != self.config["kube_node"]
                    or nodes[0]["metadata"].get("labels", {}).get("kubernetes.io/arch") != "amd64"
                    or not any(a.get("address") in addresses for a in nodes[0].get("status", {}).get("addresses", []) if a.get("type") == "InternalIP")
                    or nodes[0].get("spec", {}).get("unschedulable")
                    or not any(c.get("type") == "Ready" and c.get("status") == "True" for c in nodes[0].get("status", {}).get("conditions", []))):
                raise InstallError("k3s image import is restricted to the explicitly selected local, ready single amd64 node")

    def _object(self, kind, name, **body):
        version = "apps/v1" if kind == "Deployment" else "networking.k8s.io/v1" if kind == "NetworkPolicy" else "v1"
        metadata = {"name": name, "labels": {LABEL: self.journal.document["id"]}}
        if kind != "Namespace":
            metadata["namespace"] = self.config["kube_namespace"]
        result = dict(apiVersion=version, kind=kind, metadata=metadata, **body)
        metadata["annotations"] = {INTENT: hashlib.sha256(_canonical(result)).hexdigest()}
        return result

    def ensure(self, desired):
        """Create only from durable intent; fence later reads with exact UID."""
        key = desired["kind"] + "/" + desired["metadata"]["name"]
        records = self.journal.document["completed"].setdefault("kube-resources", {})
        desired_hash = hashlib.sha256(_canonical(desired)).hexdigest()
        prior = records.get(key)
        if prior and prior["sha256"] != desired_hash:
            raise InstallError("Kubernetes resource intent changed; use the lifecycle operation")
        current = self.get(desired["kind"], desired["metadata"]["name"])
        if not prior:
            if current:
                raise InstallError("Existing Kubernetes resource is not installer-owned; refusing adoption")
            records[key] = {"sha256": desired_hash, "uid": None}
            self.journal.save()
        if not current:
            if records[key]["uid"]:
                raise InstallError("An owned Kubernetes resource was deleted; refusing silent replacement")
            current = json.loads(self.kube("create", "-f", "-", "-o", "json", input=_canonical(desired), capture=True))
        if not _contains(current, desired):
            raise InstallError("Kubernetes resource differs from recorded installation intent")
        uid = current["metadata"].get("uid")
        if not uid or (records[key]["uid"] and uid != records[key]["uid"]):
            raise InstallError("Kubernetes resource UID changed; refusing replacement adoption")
        if not records[key]["uid"]:
            records[key]["uid"] = uid
            self.journal.save()
        return current

    def verify_resource_ownership(self):
        self.cluster_preflight()
        if not self.manifest_file.exists():
            return
        desired = json.loads(regular_bytes(self.manifest_file, 8 * 1024 * 1024))
        pending_path = self.base / "kube-update.json"
        pending = json.loads(regular_bytes(pending_path, 8 * 1024 * 1024)) if pending_path.exists() else None
        if digest(self.manifest_file) != self.journal.document["completed"].get("kube-manifests"):
            if not pending:
                raise InstallError("Kubernetes manifest custody changed")
            alternatives = []
            for version in ("before", "after"):
                candidate = copy.deepcopy(desired)
                found = False
                for index, obj in enumerate(candidate):
                    if obj["kind"] == pending[version]["kind"] and obj["metadata"]["name"] == pending[version]["metadata"]["name"]:
                        if obj not in (pending["before"], pending["after"]):
                            raise InstallError("Kubernetes pending manifest differs from approved update")
                        candidate[index] = pending[version]
                        found = True
                if found:
                    alternatives.append(hashlib.sha256(_canonical(candidate)).hexdigest())
            if self.journal.document["completed"].get("kube-manifests") not in alternatives:
                raise InstallError("Kubernetes manifest changed beyond pending object update")
        for obj in desired:
            key = obj["kind"] + "/" + obj["metadata"]["name"]
            record = self.journal.document["completed"].get("kube-resources", {}).get(key)
            if not record:
                continue
            actual = self.get(obj["kind"], obj["metadata"]["name"])
            if pending and obj["kind"] == pending["before"]["kind"] and obj["metadata"]["name"] == pending["before"]["metadata"]["name"]:
                if (not actual or record["uid"] != pending["uid"] or actual["metadata"].get("uid") != pending["uid"]
                        or obj not in (pending["before"], pending["after"])
                        or not any(_contains(actual, pending[version]) for version in ("before", "after"))):
                    raise InstallError("Kubernetes pending update ownership changed")
                continue
            if record["uid"] is None:
                if actual and not _contains(actual, obj):
                    raise InstallError("Kubernetes pending-create intent differs from cluster object")
                continue
            if not actual or actual["metadata"].get("uid") != record["uid"] or not _contains(actual, obj):
                raise InstallError("Kubernetes ownership or declared resource configuration changed")
        allowed_policies = {obj["metadata"]["name"] for obj in desired if obj["kind"] == "NetworkPolicy"}
        policies = json.loads(self.kube("get", "networkpolicies", "-o", "json", capture=True))["items"]
        if any(policy["metadata"]["name"] not in allowed_policies for policy in policies):
            raise InstallError("An unowned NetworkPolicy can broaden deployment or maintenance access")

    def prepare(self):
        # This Compose document is a LOCAL BUILD description only. Never up/run.
        super().prepare()
        self.cluster_preflight()
        if self.config["kube_registry_auth"]:
            path = Path(self.config["kube_registry_auth"])
            info = path.lstat()
            if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1:
                raise InstallError("Registry config.json must be root-owned mode 0600 without hard links")
            data = regular_bytes(path)
            auth = json.loads(data)
            if not isinstance(auth, dict) or set(auth) != {"auths"} or not isinstance(auth["auths"], dict):
                raise InstallError("Registry config must contain static auths only; credential helper execution is not supported")
            registry = self.config["kube_registry"].split("/", 1)[0]
            aliases = {registry}
            if registry == "docker.io":
                aliases.update(("index.docker.io", "https://index.docker.io/v1/"))
            selected = {name: value for name, value in auth["auths"].items() if name in aliases}
            if not selected or any(not isinstance(value, dict) or not value for value in selected.values()):
                raise InstallError("Registry config has no static credential for the selected image registry")
            # Other accounts in the operator's Docker config never enter this
            # deployment or its image-pull Secret.
            data = _canonical({"auths": selected})
            fingerprint = hashlib.sha256(data).hexdigest()
            previous = self.journal.document["completed"].get("kube-registry-auth")
            if previous and previous != fingerprint:
                raise InstallError("Registry authentication changed outside the recorded installation")
            atomic_write(self.base / "build-home/.docker/config.json", data)
            self.journal.checkpoint("kube-registry-auth", fingerprint)

    def build(self):
        super().build()
        saved = self.journal.document["completed"].get("kube-images")
        if saved:
            return
        images = {}
        specs = json.loads(regular_bytes(self.compose_file))["services"]
        for service in ("iris", "console"):
            source = specs[service]["image"]
            source_id = self.journal.document["completed"]["images"][source]
            prefix = self.config["kube_registry"] or "docker.io/iris-installer"
            repository = prefix + "/" + self.config["instance"] + "-" + service
            tag = repository + ":" + self.journal.document["id"]
            self.command(["docker", "tag", source_id, tag])
            if self.config["kube_image_import"] == "registry":
                self.command(["docker", "push", tag])
                inspected = json.loads(self.command(["docker", "image", "inspect", tag], capture=True))
                if len(inspected) != 1 or inspected[0]["Id"] != source_id:
                    raise InstallError("Published image tag changed during registry transfer")
                published = inspected[0]["RepoDigests"]
                matches = [ref for ref in published if ref.startswith(repository + "@sha256:")]
                if len(matches) != 1:
                    raise InstallError("Cannot establish the published registry image digest")
                pinned = matches[0]
            else:
                archive = self.base / ("kube-" + service + ".tar")
                self.command(["docker", "save", "--output", archive, tag])
                saved = json.loads(self.command(["skopeo", "inspect", "--raw", "docker-archive:" + str(archive)], capture=True))
                _archive_identity(archive, source_id, saved.get("config", {}).get("digest"))
                self.command(["k3s", "ctr", "images", "import", archive])
                rows = self.command(["k3s", "ctr", "images", "list"], capture=True).decode().splitlines()
                hashes = [row.split()[2] for row in rows if row.split() and row.split()[0] == tag and len(row.split()) >= 3]
                if len(hashes) != 1 or not re.fullmatch(r"sha256:[0-9a-f]{64}", hashes[0]):
                    raise InstallError("Cannot establish the imported k3s image digest")
                pinned = repository + "@" + hashes[0]
                existing = [row.split()[2] for row in rows if row.split() and row.split()[0] == pinned and len(row.split()) >= 3]
                if existing and existing != hashes:
                    raise InstallError("Imported digest reference has unexpected content")
                if not existing:
                    self.command(["k3s", "ctr", "images", "tag", tag, pinned])
            if not re.fullmatch(r"[^@\s]+@sha256:[0-9a-f]{64}", pinned):
                raise InstallError("Container image is not digest pinned")
            images[service] = pinned
        self.journal.checkpoint("kube-images", images)

    def _certificate(self, name, hosts):
        key, cert = self.base / (name + ".key"), self.base / (name + ".crt")
        if not key.exists() and not cert.exists():
            self.command(["openssl", "req", "-x509", "-newkey", "rsa:3072", "-nodes", "-days", "90",
                          "-subj", "/CN=" + hosts[0].split(":", 1)[1], "-addext", "subjectAltName=" + ",".join(hosts),
                          "-keyout", key, "-out", cert])
            key.chmod(0o600)
        if not key.is_file() or not cert.is_file():
            raise InstallError("Incomplete TLS custody; preserve the installation state")
        return {"tls.key": regular_bytes(key, 65536), "tls.crt": regular_bytes(cert, 65536)}

    def _secret(self, name, values):
        return self._object("Secret", name, type="Opaque", data={k: base64.b64encode(v).decode() for k, v in values.items()})

    def manifests(self):
        if self.manifest_file.exists():
            expected = self.journal.document["completed"].get("kube-manifests")
            if expected != digest(self.manifest_file):
                raise InstallError("Kubernetes manifest custody changed")
            return json.loads(regular_bytes(self.manifest_file, 8 * 1024 * 1024))
        namespace = self.config["kube_namespace"]
        management = self._certificate("kube-management", ["DNS:iris-server-api", "DNS:iris-server-api." + namespace + ".svc"])
        browser = self._certificate("kube-browser", ["IP:" + self.config["console_bind"]])
        token_path = self.base / "kube-token.json"
        if not token_path.exists():
            atomic_write(token_path, _canonical({"scope": "management", "token": secrets.token_urlsafe(48)}))
        recipient = self.command(["age-keygen", "-y", self.base / "age.txt"], capture=True).decode().strip()
        server_env = {}
        for line in (self.source / "kubernetes/iris-seed-server.env").read_text().splitlines():
            if line.strip() and not line.startswith("#"):
                key, value = line.split("=", 1)
                server_env[key] = value
        server_env.update(IRIS_HOST_IP=self.config["host"], IRIS_AGE_RECIPIENTS=recipient + "," + self.config["recovery_recipient"],
                          IRIS_PEER_TLS_MODE=self.config["peer_tls"], IRIS_AGE_KEY_FILE="/run/secrets/age/identity",
                          IRIS_MANAGEMENT_API_TOKEN_FILE="/data/config/tier/current.json", IRIS_MANAGEMENT_API_PREVIOUS_TOKEN_FILE="/data/config/tier/previous.json",
                          IRIS_MANAGEMENT_API_CERT="/run/secrets/management/tls.crt", IRIS_MANAGEMENT_API_KEY="/run/secrets/management/tls.key",
                          IRIS_GUI_FALLBACK_GENERATE="1", IRIS_GUI_FALLBACK_CERT="/run/iris/tls/console-fallback.pem",
                          IRIS_INSTALLER_TARGET="kubernetes",
                          IRIS_INSTALLER_SHUTDOWN_PROOF="/data/state/installer-shutdown.json",
                          IRIS_CONSOLE_URL=f'https://{self.config["console_bind"]}:{self.config["console_port"]}/')
        from .lifecycle_network import prepare_network_custody
        custody = prepare_network_custody(self.base, self.config["lifecycle_url"], self.command)
        server_env.update(IRIS_LIFECYCLE_URL=self.config["lifecycle_url"],
                          IRIS_LIFECYCLE_CA="/run/secrets/lifecycle/ca.crt",
                          IRIS_LIFECYCLE_CERT="/run/secrets/lifecycle/client.crt",
                          IRIS_LIFECYCLE_KEY="/run/secrets/lifecycle/client.key")
        console_env = dict(IRIS_GUI_HOST="0.0.0.0", IRIS_GUI_PORT="8080", PYTHONDONTWRITEBYTECODE="1",
                           IRIS_MANAGEMENT_API_URL="https://iris-server-api:9443",
                           IRIS_MANAGEMENT_API_TOKEN_FILE="/run/secrets/tier/current", IRIS_MANAGEMENT_API_PREVIOUS_TOKEN_FILE="/run/secrets/tier/previous",
                           IRIS_MANAGEMENT_API_CA="/run/config/management/ca.crt", IRIS_GUI_CERT="/run/iris/console-cert.pem",
                           IRIS_GUI_DEFAULT_CERT="/run/secrets/browser/tls.crt", IRIS_GUI_DEFAULT_KEY="/run/secrets/browser/tls.key")
        from .deploy import read_roots
        result = [self._object("Namespace", namespace),
                  self._object("PersistentVolumeClaim", "iris-data", spec={"accessModes": ["ReadWriteOnce"], "storageClassName": self.config["kube_storage_class"], "resources": {"requests": {"storage": self.config["kube_storage_size"]}}}),
                  self._secret("iris-age", {"identity": regular_bytes(self.base / "age.txt", 65536)}),
                  self._secret("iris-lifecycle", {name: regular_bytes(custody[name], 65536) for name in ("ca.crt", "client.crt", "client.key")}),
                  self._secret("iris-tier-auth", {"current": regular_bytes(token_path), "previous": b""}),
                  self._secret("iris-management-tls", management), self._secret("iris-console-tls", browser),
                  self._object("ConfigMap", "iris-management-ca", data={"ca.crt": management["tls.crt"].decode()}),
                  self._object("ConfigMap", "iris-public-roots", data={k: v.decode() for k, v in read_roots(self.base / "roots").items()}),
                  self._object("ConfigMap", "iris-seed-server", data=server_env),
                  self._object("ConfigMap", "iris-console", data=console_env)]
        if self.config["kube_registry_auth"]:
            pull_secret = self._secret("iris-registry", {".dockerconfigjson": regular_bytes(self.base / "build-home/.docker/config.json")})
            pull_secret["type"] = "kubernetes.io/dockerconfigjson"
            result.append(pull_secret)
        for service in ("iris", "console"):
            name = SERVICES[service]
            pod = self._pod_spec(service)
            labels = {LABEL: self.journal.document["id"], "app.kubernetes.io/name": name}
            result.append(self._object("Deployment", name, spec={"replicas": 1 if service == "iris" else self.config["kube_console_replicas"], "strategy": {"type": "Recreate"}, "selector": {"matchLabels": labels}, "template": {"metadata": {"labels": labels}, "spec": pod}}))
        for name, service, ports, external in (
                ("iris-seed-server", "iris", [6969, 8443, 8000, 6881, 9101], self.config["host"]),
                ("iris-server-api", "iris", [9443], None),
                ("iris-console", "console", [self.config["console_port"]], self.config["console_bind"])):
            spec = {"selector": {LABEL: self.journal.document["id"], "app.kubernetes.io/name": SERVICES[service]},
                    "ports": [{"name": "tcp-" + str(p), "port": p, "targetPort": 8080 if service == "console" else p, "protocol": "TCP"} for p in ports]}
            if external:
                spec.update(type="LoadBalancer", loadBalancerIP=external, externalTrafficPolicy="Local")
            result.append(self._object("Service", name, spec=spec))
        result.append(self._object("NetworkPolicy", "iris-default-deny-ingress", spec={"podSelector": {"matchLabels": {LABEL: self.journal.document["id"]}}, "policyTypes": ["Ingress"], "ingress": []}))
        for service, ports in (("iris", [6969, 8443, 8000, 6881, 9101]), ("console", [8080])):
            rules = [{"ports": [{"port": p, "protocol": "TCP"} for p in ports]}]
            if service == "iris":
                rules.append({"from": [{"podSelector": {"matchLabels": {LABEL: self.journal.document["id"], "app.kubernetes.io/name": SERVICES["console"]}}}], "ports": [{"port": 9443, "protocol": "TCP"}]})
            result.append(self._object("NetworkPolicy", SERVICES[service] + "-ingress", spec={"podSelector": {"matchLabels": {LABEL: self.journal.document["id"], "app.kubernetes.io/name": SERVICES[service]}}, "policyTypes": ["Ingress"], "ingress": rules}))
        atomic_write(self.manifest_file, _canonical(result))
        self.journal.checkpoint("kube-manifests", digest(self.manifest_file))
        return result

    def _pod_spec(self, service):
        server = service == "iris"
        security = {"runAsNonRoot": True, "runAsUser": 10001, "runAsGroup": 10001, "fsGroup": 10001,
                    "fsGroupChangePolicy": "OnRootMismatch", "seccompProfile": {"type": "RuntimeDefault"}}
        volumes = [{"name": "runtime", "emptyDir": {"medium": "Memory"}}, {"name": "tmp", "emptyDir": {}}]
        mounts = [{"name": "runtime", "mountPath": "/run/iris"}, {"name": "tmp", "mountPath": "/tmp"}]
        secrets_to_mount = [("tier", "iris-tier-auth")]
        if server:
            volumes += [{"name": "data", "persistentVolumeClaim": {"claimName": "iris-data"}}, {"name": "roots", "configMap": {"name": "iris-public-roots"}}]
            mounts += [{"name": "data", "mountPath": "/data"}, {"name": "roots", "mountPath": "/public-roots", "readOnly": True}]
            secrets_to_mount += [("age", "iris-age"), ("management", "iris-management-tls"), ("lifecycle", "iris-lifecycle")]
        else:
            volumes += [{"name": "management-ca", "configMap": {"name": "iris-management-ca"}}]
            mounts += [{"name": "management-ca", "mountPath": "/run/config/management", "readOnly": True}]
            secrets_to_mount += [("browser", "iris-console-tls")]
        for name, secret in secrets_to_mount:
            volumes.append({"name": name, "secret": {"secretName": secret, "defaultMode": 0o440}})
            mounts.append({"name": name, "mountPath": "/run/secrets/" + name, "readOnly": True})
        container = {"name": service, "image": self.journal.document["completed"]["kube-images"][service],
                     "imagePullPolicy": "Never" if self.config["kube_image_import"] == "k3s" else "IfNotPresent",
                     "envFrom": [{"configMapRef": {"name": SERVICES[service]}}], "volumeMounts": mounts,
                     "securityContext": {"allowPrivilegeEscalation": False, "capabilities": {"drop": ["ALL"]}},
                     "resources": {"requests": {"cpu": "100m", "memory": "128Mi"}, "limits": {"cpu": "2" if server else "1", "memory": "2Gi" if server else "512Mi"}}}
        port = 9101 if server else 8080
        for probe, path in (("startupProbe", "/readyz"), ("readinessProbe", "/readyz"), ("livenessProbe", "/healthz")):
            container[probe] = {"httpGet": {"path": path, "port": port, "scheme": "HTTPS"}, "periodSeconds": 5 if probe == "startupProbe" else 10, "timeoutSeconds": 10, "failureThreshold": 60 if probe == "startupProbe" else 6}
        spec = {"automountServiceAccountToken": False, "terminationGracePeriodSeconds": 180,
                "securityContext": security, "nodeSelector": {"kubernetes.io/arch": "amd64"}, "volumes": volumes, "containers": [container]}
        if self.config["kube_node"]:
            spec["nodeSelector"]["kubernetes.io/hostname"] = self.config["kube_node"]
        if self.config["kube_registry_auth"]:
            spec["imagePullSecrets"] = [{"name": "iris-registry"}]
        if server:
            container["env"] = [{"name": "IRIS_POD_UID", "valueFrom": {"fieldRef": {"apiVersion": "v1", "fieldPath": "metadata.uid"}}}]
            # A newly provisioned fsGroup volume may set SGID on new children.
            # Create private authority dirs ourselves and explicitly clear it.
            init = copy.deepcopy(container)
            init["name"] = "bootstrap"
            for probe in ("startupProbe", "readinessProbe", "livenessProbe"):
                del init[probe]
            init["command"] = ["/bin/sh", "-c"]
            init["args"] = ['set -eu; for d in /data/state /data/config /data/log /data/images /data/artifacts; do '
                            '[ ! -L "$d" ]; if [ ! -e "$d" ]; then mkdir -m 0700 "$d"; chmod 00700 "$d"; fi; done; '
                            'iris-bootstrap; install -d -m 0700 /data/config/tier; '
                            'if [ ! -e /data/config/tier/current.json ]; then '
                            '[ ! -e /data/config/tier/previous.json ]; install -m 0600 /run/secrets/tier/current /data/config/tier/current.json; '
                            'install -m 0600 /run/secrets/tier/previous /data/config/tier/previous.json; fi; '
                            'install -d -m 0755 /data/config/instr/roots.d; '
                            'for f in /public-roots/*.pub; do n="$(basename "$f")"; '
                            'if [ -e "/data/config/instr/roots.d/$n" ]; then cmp "$f" "/data/config/instr/roots.d/$n"; '
                            'else install -m 0644 "$f" "/data/config/instr/roots.d/$n"; fi; done']
            spec["initContainers"] = [init]
        else:
            container["command"] = ["python3", "/opt/iris/server/gui_server.py"]
        return spec

    def bootstrap(self):
        objects = self.manifests()
        # Network restrictions are installed before any runnable workload.
        for obj in objects:
            if obj["kind"] != "Deployment":
                self.ensure(obj)
        self.ensure(next(o for o in objects if o["kind"] == "Deployment" and o["metadata"]["name"] == SERVICES["iris"]))
        self.kube("rollout", "status", "deployment/iris-seed-server", "--timeout=300s", timeout=330)
        self.journal.checkpoint("server", True)

    def _pods(self, service):
        deployment = self.get("deployment", SERVICES[service])
        key = "Deployment/" + SERVICES[service]
        record = self.journal.document["completed"].get("kube-resources", {}).get(key)
        if not deployment or not record or deployment["metadata"].get("uid") != record["uid"]:
            raise InstallError("Workload ownership changed")
        declared = next(o for o in self.manifests() if o["kind"] == "Deployment" and o["metadata"]["name"] == SERVICES[service])
        if not _contains(deployment, declared):
            raise InstallError("Workload specification changed")
        replicasets = json.loads(self.kube("get", "replicasets", "-l", LABEL + "=" + self.journal.document["id"], "-o", "json", capture=True))["items"]
        owned = {r["metadata"]["uid"] for r in replicasets if any(o.get("uid") == record["uid"] and o.get("controller") for o in r["metadata"].get("ownerReferences", []))}
        pods = json.loads(self.kube("get", "pods", "-l", "app.kubernetes.io/name=" + SERVICES[service], "-o", "json", capture=True))["items"]
        valid = []
        for pod in pods:
            if pod["metadata"].get("deletionTimestamp") or pod.get("status", {}).get("phase") != "Running":
                continue
            if (pod["metadata"].get("labels", {}).get(LABEL) != self.journal.document["id"]
                    or not any(o.get("uid") in owned and o.get("controller") for o in pod["metadata"].get("ownerReferences", []))
                    or pod["spec"]["containers"][0]["image"] != self.journal.document["completed"]["kube-images"][service]):
                raise InstallError("Pod ownership or immutable image changed")
            expected_pod = {"kind": "Pod", "metadata": {"labels": declared["spec"]["template"]["metadata"]["labels"]},
                            "spec": declared["spec"]["template"]["spec"]}
            if not _contains(pod, expected_pod):
                raise InstallError("Pod execution or storage differs from the owned workload")
            if not any(c.get("type") == "Ready" and c.get("status") == "True" for c in pod.get("status", {}).get("conditions", [])):
                raise InstallError("Expected workload pod is not ready")
            valid.append({"name": pod["metadata"]["name"], "uid": pod["metadata"]["uid"]})
        expected = 1 if service == "iris" else self.config["kube_console_replicas"]
        if len(valid) != expected:
            raise InstallError("Expected owned running workload is unavailable")
        return sorted(valid, key=lambda p: p["name"])

    def _pod(self, service):
        return self._pods(service)[0]["name"]

    def execute(self, *args, **kwargs):
        return self.kube("exec", "-i", self._pod("iris"), "-c", "iris", "--", *args, **kwargs)

    def execute_console(self, *args, **kwargs):
        return self.kube("exec", "-i", self._pod("console"), "-c", "console", "--", *args, **kwargs)

    def packages(self):
        if "packages" not in self.journal.document["completed"]:
            self.command(["bash", self.source / "tools/get-ioxclient.sh", self.base / "bin"])
            for arch in ("arm64", "amd64"):
                self.command(["bash", self.source / "tools/stage-iox-package.sh", "--arch", arch, "--artifacts-dir", self.base / "artifacts"])
            self.command(["bash", self.source / "tools/build-xr-package.sh", "--out", self.base / "artifacts"])
            self.journal.checkpoint("packages", {p.name: digest(p) for name in ("iris-amd64.tar", "iris-arm64.tar", "iris-xr.rpm") for p in (self.base / "artifacts" / name, self.base / "artifacts" / (name + ".manifest"))})
        for name, expected in self.journal.document["completed"]["packages"].items():
            if not re.fullmatch(r"iris-(?:amd64\.tar|arm64\.tar|xr\.rpm)(?:\.manifest)?", name) or not re.fullmatch(r"[0-9a-f]{64}", expected):
                raise InstallError("Native package checkpoint contains an unsupported artifact")
            path = self.base / "artifacts" / name
            if digest(path) != expected:
                raise InstallError("Native build artifact changed")
            # No kubectl cp/tar extraction. Fixed basenames and same-uid atomic
            # files avoid the root-owned package failure this installer fixes.
            code = ("import os,sys,hashlib,tempfile; from pathlib import Path; "
                    "p=Path(os.environ['IRIS_ARTIFACTS_DIR'])/sys.argv[1]; "
                    "assert os.geteuid()==10001 and not p.is_symlink(); "
                    "data=sys.stdin.buffer.read(); assert hashlib.sha256(data).hexdigest()==sys.argv[2]; "
                    "fd,tmp=tempfile.mkstemp(dir=p.parent); f=os.fdopen(fd,'wb'); f.write(data); f.flush(); os.fsync(f.fileno()); "
                    "os.fchmod(f.fileno(),0o644); f.close(); os.replace(tmp,p)")
            self.execute("python3", "-I", "-B", "-c", code, name, expected, input=regular_bytes(path, 1024 * 1024 * 1024))
        self.execute("/opt/iris/server/provision-served.sh")
        from .cli import validate_report
        report = json.loads(self.execute("python3", "-I", "-B", "-", input=Path(__file__).with_name("probe.py").read_bytes(), capture=True))
        validate_report(report, optional_xr=False)
        if report["state"] != "checks-passed":
            raise InstallError("Kubernetes native-package runtime checks failed")
        self.journal.checkpoint("kube-package-proof", report)
        guest = json.loads(self.python("import setup_status,os,json; print(json.dumps(setup_status.served_bundle_readiness(os.environ['IRIS_ARTIFACTS_DIR'],os.path.join(os.environ['IRIS_RUN'],'served-bundle.json'),startup_state='ok')))"))
        if guest.get("state") != "ok":
            raise InstallError("Kubernetes Guest Shell verification failed")
        self.journal.checkpoint("guestshell", guest)

    def finish(self):
        self.ensure(next(o for o in self.manifests() if o["kind"] == "Deployment" and o["metadata"]["name"] == SERVICES["console"]))
        self.kube("rollout", "status", "deployment/iris-console", "--timeout=300s", timeout=330)
        # Prove the authenticated hop from the actual Console, with CA and DNS
        # verification intact, without creating an owner or browser session.
        self.lifecycle_consumer_proof()
        public_certificate = self.execute_console("openssl", "x509", "-in", "/run/iris/console-cert.pem", "-outform", "PEM", capture=True)
        atomic_write(self.base / "requests/console-cert.pem", public_certificate, 0o644)
        self.verify_external_services(public_certificate)
        claimed = self.python("import gui_auth,secrets_store,os; print(bool(gui_auth.get_admin(secrets_store.load(os.environ['IRIS_SECRETS']))))").strip()
        if claimed not in (b"True", b"False"):
            raise InstallError("Cannot establish Console ownership")
        self.journal.pause("OWNER_CLAIM_REQUIRED" if claimed == b"False" else "PRODUCTION_REVIEW_REQUIRED")
        print("Console: https://" + self.config["console_bind"] + ":" + str(self.config["console_port"]) + "/; no owner was created or logged in")
        return OWNER_CLAIM if claimed == b"False" else PRODUCTION_REVIEW

    def verify_external_services(self, console_certificate):
        for service, address in (("iris-seed-server", self.config["host"]), ("iris-console", self.config["console_bind"])):
            self.kube("wait", "--for=jsonpath={.status.loadBalancer.ingress[0].ip}=" + address,
                      "service/" + service, "--timeout=180s", timeout=210)
            current = self.get("service", service)
            if [item.get("ip") for item in current.get("status", {}).get("loadBalancer", {}).get("ingress", [])] != [address]:
                raise InstallError("LoadBalancer did not allocate the exact requested deployment address")
        device_certificate = self.execute("openssl", "x509", "-in", "/run/iris/tls/cert.pem", "-outform", "PEM", capture=True)
        try:
            device_tls = ssl.create_default_context(cadata=device_certificate.decode())
            console_tls = ssl.create_default_context(cadata=console_certificate.decode())
            endpoints = [(self.config["host"], port, device_tls) for port in (6969, 8443, 8000, 9101)]
            endpoints.append((self.config["console_bind"], self.config["console_port"], console_tls))
            for address, port, context in endpoints:
                with socket.create_connection((address, port), timeout=8) as sock:
                    with context.wrap_socket(sock, server_hostname=address):
                        pass
            with socket.create_connection((self.config["host"], 6881), timeout=8):
                pass
        except (OSError, ValueError, UnicodeError):
            raise InstallError("External deployment listeners are unreachable or their TLS identities differ from the owned workload") from None
        self.journal.checkpoint("kube-external-services", {"server": self.config["host"], "console": self.config["console_bind"], "verified": True})

    def resume(self, certificate=None):
        operation = self.base / "credential-operation.json"
        if operation.exists() or operation.is_symlink():
            authority = json.loads(regular_bytes(operation))
            if (authority.get("instance_id") != self.journal.document["id"]
                    or not (authority.get("phase") == "rotated" or (authority.get("phase") == "refused" and authority.get("mutations_admitted") is False))):
                raise InstallError("Recover the approved credential operation before resuming installation")
        self.verify_inputs()
        from . import ubuntu
        ubuntu.provision(self.command)
        ubuntu.provision_kubernetes_client(self.command)
        self.verify_resource_ownership()
        self.command(["bash", self.source / "tools/check-host-time.sh"], timeout=30)
        self.prepare()
        self.build()
        self.bootstrap()
        if not self.signing(certificate):
            return WAITING_APPROVAL
        self.packages()
        return self.finish()

    def lifecycle_consumer_proof(self):
        code = '''import os,sys,ssl,http.client,hashlib,json
sys.path.insert(0,'/opt/iris/server')
import tier_auth
from urllib.parse import urlsplit
u=urlsplit(os.environ['IRIS_MANAGEMENT_API_URL'])
c=http.client.HTTPSConnection(u.hostname,u.port or 443,timeout=15,context=ssl.create_default_context(cafile=os.environ['IRIS_MANAGEMENT_API_CA']))
t,_=tier_auth.load_pair(os.environ['IRIS_MANAGEMENT_API_TOKEN_FILE'])
c.connect()
fingerprint=hashlib.sha256(c.sock.getpeercert(binary_form=True)).hexdigest()
c.request('GET','/internal/v1/console-certificate',headers={'Authorization':'Bearer '+t.decode(),'X-IRIS-Default-Certificate':'available'})
r=c.getresponse()
if r.status not in (200,204): raise RuntimeError('authentication')
c.close()
print(json.dumps({'management_https':'verified','certificate_sha256':fingerprint}))
'''
        pods = self._pods("console")
        proofs = []
        for pod in pods:
            current = self.get("pod", pod["name"])
            if not current or current["metadata"].get("uid") != pod["uid"]:
                raise InstallError("Console pod changed during consumer verification")
            result = json.loads(self.kube("exec", "-i", pod["name"], "-c", "console", "--", "python3", "-I", "-B", "-c", code, capture=True, timeout=30))
            if (result.get("management_https") != "verified" or not re.fullmatch(r"[0-9a-f]{64}", result.get("certificate_sha256", ""))):
                raise InstallError("Authenticated Kubernetes Console consumer proof failed")
            proofs.append(dict(result, pod_uid=pod["uid"]))
        if self._pods("console") != pods or len({p["certificate_sha256"] for p in proofs}) != 1:
            raise InstallError("Console replicas changed or observed different management identities")
        return {"management_https": "verified", "certificate_sha256": proofs[0]["certificate_sha256"], "console_consumers": proofs}

    def pin_runtime(self):
        self.verify_resource_ownership()
        images = self.journal.document["completed"].get("kube-images", {})
        if set(images) != {"iris", "console"} or any(not re.fullmatch(r"[^@\s]+@sha256:[0-9a-f]{64}", value) for value in images.values()):
            raise InstallError("Kubernetes lifecycle requires immutable image pins")

    def _recover_object_update(self):
        path = self.base / "kube-update.json"
        if not path.exists() and not path.is_symlink():
            return
        pending = json.loads(regular_bytes(path, 8 * 1024 * 1024))
        if not isinstance(pending, dict) or set(pending) != {"before", "after", "uid"}:
            raise InstallError("Kubernetes update authority is invalid")
        before, after = pending["before"], pending["after"]
        if (before["kind"] != after["kind"] or before["metadata"]["name"] != after["metadata"]["name"]
                or before["metadata"].get("labels", {}).get(LABEL) != self.journal.document["id"]
                or after["metadata"].get("labels", {}).get(LABEL) != self.journal.document["id"]):
            raise InstallError("Kubernetes pending update escapes installation ownership")
        key = before["kind"] + "/" + before["metadata"]["name"]
        record = self.journal.document["completed"].get("kube-resources", {}).get(key)
        if not record or record.get("uid") != pending["uid"]:
            raise InstallError("Kubernetes update UID differs from ownership custody")
        objects = json.loads(regular_bytes(self.manifest_file, 8 * 1024 * 1024))
        index = next((i for i, o in enumerate(objects) if o["kind"] == before["kind"] and o["metadata"]["name"] == before["metadata"]["name"]), None)
        if index is None or objects[index] not in (before, after):
            raise InstallError("Kubernetes resource file changed outside pending update")
        actual = self.get(before["kind"], before["metadata"]["name"])
        if not actual or actual["metadata"].get("uid") != pending["uid"]:
            raise InstallError("Kubernetes update target was replaced")
        if _contains(actual, after):
            objects[index] = after
            atomic_write(self.manifest_file, _canonical(objects))
            record["sha256"] = hashlib.sha256(_canonical(after)).hexdigest()
            self.journal.document["completed"]["kube-manifests"] = digest(self.manifest_file)
            self.journal.save()
            path.unlink()
        elif _contains(actual, before):
            # Nothing was applied. Restore only the recorded public/secret
            # description, not any PVC data, and retry the same exact intent.
            objects[index] = before
            atomic_write(self.manifest_file, _canonical(objects))
            record["sha256"] = hashlib.sha256(_canonical(before)).hexdigest()
            self.journal.document["completed"]["kube-manifests"] = digest(self.manifest_file)
            self.journal.save()
            self._replace_owned(after)
        else:
            raise InstallError("Kubernetes pending update found neither original nor approved bytes")

    def _replace_owned(self, desired):
        """UID/resourceVersion compare-and-swap, with recoverable disk intent."""
        objects = self.manifests()
        kind, name = desired["kind"], desired["metadata"]["name"]
        key = kind + "/" + name
        prior = next((o for o in objects if o["kind"] == kind and o["metadata"]["name"] == name), None)
        record = self.journal.document["completed"].get("kube-resources", {}).get(key)
        if not prior or not record or not record.get("uid"):
            raise InstallError("Cannot update an unowned Kubernetes object")
        desired = copy.deepcopy(desired)
        desired["metadata"].pop("annotations", None)
        desired["metadata"]["annotations"] = {INTENT: hashlib.sha256(_canonical(desired)).hexdigest()}
        pending_path = self.base / "kube-update.json"
        if pending_path.exists():
            pending = json.loads(regular_bytes(pending_path, 8 * 1024 * 1024))
            if pending != {"before": prior, "after": desired, "uid": record["uid"]}:
                raise InstallError("A different Kubernetes object update requires recovery")
        else:
            atomic_write(pending_path, _canonical({"before": prior, "after": desired, "uid": record["uid"]}))
        current = self.get(kind, name)
        if not current or current["metadata"].get("uid") != record["uid"]:
            raise InstallError("Kubernetes object was replaced during maintenance")
        if not _contains(current, desired):
            if not _contains(current, prior):
                raise InstallError("Kubernetes object changed outside this approved update")
            replacement = copy.deepcopy(desired)
            replacement["metadata"].update(uid=record["uid"], resourceVersion=current["metadata"]["resourceVersion"])
            # Preserve apiserver-managed Service/PVC immutable allocation fields.
            if kind in ("Service", "PersistentVolumeClaim"):
                for field in ("clusterIP", "clusterIPs", "ipFamilies", "ipFamilyPolicy", "volumeName"):
                    if field in current.get("spec", {}):
                        replacement.setdefault("spec", {}).setdefault(field, current["spec"][field])
            current = json.loads(self.kube("replace", "-f", "-", "-o", "json", input=_canonical(replacement), capture=True))
        if current["metadata"].get("uid") != record["uid"] or not _contains(current, desired):
            raise InstallError("Kubernetes update returned unexpected identity or contents")
        objects[objects.index(prior)] = desired
        atomic_write(self.manifest_file, _canonical(objects))
        record["sha256"] = hashlib.sha256(_canonical(desired)).hexdigest()
        self.journal.document["completed"]["kube-manifests"] = digest(self.manifest_file)
        self.journal.save()
        pending_path.unlink()

    def scale(self, service, replicas):
        objects = self.manifests()
        desired = copy.deepcopy(next(o for o in objects if o["kind"] == "Deployment" and o["metadata"]["name"] == SERVICES[service]))
        if desired["spec"]["replicas"] == replicas:
            self.ensure(desired)
            return
        desired["spec"]["replicas"] = replicas
        self._replace_owned(desired)

    def assert_writers_stopped(self):
        self.verify_resource_ownership()
        for service in ("iris", "console"):
            deployment = self.get("deployment", SERVICES[service])
            if not deployment or deployment["spec"].get("replicas") != 0:
                raise InstallError("Both Kubernetes deployments must be scaled to zero")
        pods = json.loads(self.kube("get", "pods", "-o", "json", capture=True))["items"]
        helper = self.journal.document["completed"].get("kube-helper", {})
        for pod in pods:
            uses_data = any(v.get("persistentVolumeClaim", {}).get("claimName") == "iris-data" for v in pod.get("spec", {}).get("volumes", []))
            workload = pod["metadata"].get("labels", {}).get("app.kubernetes.io/name") in SERVICES.values()
            matching_helper = pod["metadata"].get("uid") == helper.get("uid")
            if not matching_helper and helper.get("uid") is None and pod["metadata"]["name"] == helper.get("name"):
                intent = json.loads(regular_bytes(self.base / "kube-helper.json"))
                matching_helper = helper.get("sha256") == digest(self.base / "kube-helper.json") and _contains(pod, intent)
            if (uses_data or workload) and not matching_helper:
                raise InstallError("A Kubernetes workload can still access deployment storage")

    def stop_writers(self, containers, *, recovering_clean_operation=False):
        if getattr(self, "credential_recovery", False):
            self._recover_object_update()
        self.pin_runtime()
        proof = self.journal.document["completed"].get("kube-clean-stop")
        server = self.get("deployment", SERVICES["iris"])
        transaction = getattr(self, "credential_transaction", None)
        recovering_restart = bool(transaction is not None
            and transaction.record.get("initial_clean_stop") is True
            and transaction.record.get("mutations_admitted") is True)
        if server["spec"].get("replicas", 0) > 0 and not recovering_restart:
            try:
                pod = self._pods("iris")[0]
                nonce = self.execute("cat", "/run/iris/installer-shutdown-nonce", capture=True).decode().strip()
                if not re.fullmatch(r"[0-9a-f]{32,128}", nonce):
                    raise InstallError("Server runtime lacks an auditable shutdown nonce")
                proof = {"pod_uid": pod["uid"], "nonce": nonce, "verified": False}
                self.journal.checkpoint("kube-clean-stop", proof)
            except InstallError:
                if not recovering_restart or not proof or not proof.get("verified"):
                    raise
                # The initial verified backup already exists. A failed new
                # writer is fenced by Deployment UID and stopped before the
                # same-ID old-or-approved credential recovery can proceed.
        elif not recovering_restart and (not proof or (not proof.get("verified") and not recovering_clean_operation)):
            raise InstallError("Stopped server lacks retained clean-shutdown authority")
        for service in ("console", "iris"):
            self.scale(service, 0)
            self.kube("wait", "--for=delete", "pods", "-l", "app.kubernetes.io/name=" + SERVICES[service], "--timeout=180s", timeout=210)
        self.assert_writers_stopped()
        self.maintenance_open()
        if proof and not proof.get("verified") and not recovering_restart:
            raw = self.maintenance_run(["python3", "-I", "-B", "-c",
                "from pathlib import Path; import sys; p=Path('/data/state/installer-shutdown.json'); assert not p.is_symlink(); sys.stdout.buffer.write(p.read_bytes())"], capture=True)
            observed = json.loads(raw)
            children = observed.get("children")
            if (observed.get("pod_uid") != proof["pod_uid"] or observed.get("nonce") != proof["nonce"]
                    or observed.get("clean") is not True or not isinstance(children, list) or not children
                    or any(type(child.get("exit_code")) is not int or child["exit_code"] not in (0, 143) for child in children)):
                raise InstallError("Server did not provide matching clean-shutdown proof; backup refused")
            proof["verified"] = True
            self.journal.checkpoint("kube-clean-stop", proof)
        # Refresh only after every writer is stopped. The snapshot is not a
        # rollback source; publication uses per-file old-or-approved hashes.

    def maintenance_open(self, *, seeder_operation=None):
        self.assert_writers_stopped()
        self._ensure_maintenance_isolation()
        if seeder_operation is not None:
            try:
                if str(uuid.UUID(seeder_operation)) != seeder_operation:
                    raise ValueError
            except (TypeError, ValueError):
                raise InstallError("Invalid seeder operation identifier") from None
        name = "iris-maintenance-" + self.journal.document["id"][:8] + ("-seed" if seeder_operation else "")
        spec = self._pod_spec("iris")
        spec.pop("initContainers", None)
        spec["restartPolicy"] = "Never"
        container = spec["containers"][0]
        for probe in ("startupProbe", "readinessProbe", "livenessProbe"):
            container.pop(probe, None)
        if seeder_operation:
            container["command"] = ["/opt/iris/server/docker-entrypoint.sh"]
            container["env"] = [{"name": name, "value": value} for name, value in {
                "IRIS_MAINTENANCE_SEEDER_ONLY": "1", "IRIS_TRACKER_ANNOUNCE": "https://127.0.0.1:6969/announce",
                "IRIS_TELEMETRY_CA": "/run/iris/tls/maintenance-crt.pem", "IRIS_INSTALLER_SHUTDOWN_PROOF": ""}.items()]
        else:
            container["command"] = ["python3", "-I", "-B", "-c",
                "import os,time; os.makedirs('/run/iris/instr',mode=0o700,exist_ok=True); os.chmod('/run/iris/instr',0o700); time.sleep(86400)"]
        desired = self._object("Pod", name, spec=spec)
        desired["metadata"]["labels"]["iris.cisco.com/maintenance"] = "true"
        prior = self.journal.document["completed"].get("kube-helper")
        current = self.get("pod", name)
        if prior:
            if prior["name"] != name or prior.get("sha256") != hashlib.sha256(_canonical(desired)).hexdigest():
                raise InstallError("Maintenance helper identity changed; preserve the stopped deployment")
            if current and (prior["uid"] not in (None, current["metadata"].get("uid")) or not _contains(current, desired)):
                raise InstallError("Maintenance helper identity changed; preserve the stopped deployment")
            if not current and prior["uid"] is not None:
                raise InstallError("Maintenance helper was deleted; preserve its operation authority")
        else:
            if current:
                raise InstallError("An unowned maintenance helper already exists")
            atomic_write(self.base / "kube-helper.json", _canonical(desired))
            self.journal.checkpoint("kube-helper", {"name": name, "uid": None, "seeder_operation": seeder_operation,
                "sha256": digest(self.base / "kube-helper.json")})
        if not current:
            current = json.loads(self.kube("create", "-f", "-", "-o", "json", input=_canonical(desired), capture=True))
        if not self.journal.document["completed"]["kube-helper"]["uid"]:
            self.journal.document["completed"]["kube-helper"]["uid"] = current["metadata"]["uid"]
            self.journal.save()
        self.kube("wait", "--for=condition=Ready", "pod/" + name, "--timeout=180s", timeout=210)
        return name

    def maintenance_run(self, argv, *, input=None, capture=False, timeout=7200):
        self.assert_writers_stopped()
        helper = self.journal.document["completed"].get("kube-helper")
        if not helper:
            self.maintenance_open()
            helper = self.journal.document["completed"]["kube-helper"]
        current = self.get("pod", helper["name"])
        desired = json.loads(regular_bytes(self.base / "kube-helper.json"))
        if (not current or current["metadata"].get("uid") != helper["uid"]
                or helper.get("sha256") != digest(self.base / "kube-helper.json") or not _contains(current, desired)):
            raise InstallError("Maintenance helper UID changed")
        return self.kube("exec", "-i", helper["name"], "-c", "iris", "--", *argv, input=input, capture=capture, timeout=timeout)

    def maintenance_close(self):
        helper = self.journal.document["completed"].get("kube-helper")
        if not helper:
            return
        current = self.get("pod", helper["name"])
        if current:
            if current["metadata"].get("uid") != helper["uid"]:
                raise InstallError("Refusing to delete an unowned replacement helper")
            endpoint = "/api/v1/namespaces/" + self.config["kube_namespace"] + "/pods/" + helper["name"]
            self.kube("delete", "--raw", endpoint, "-f", "-", input=_canonical({"apiVersion": "v1", "kind": "DeleteOptions", "preconditions": {"uid": helper["uid"]}}))
            self.kube("wait", "--for=delete", "pod/" + helper["name"], "--timeout=180s", timeout=210)
        del self.journal.document["completed"]["kube-helper"]
        self.journal.save()

    def restart_writer(self, container):
        self.maintenance_close()
        service = container["service"]
        self.scale(service, 1 if service == "iris" else self.config["kube_console_replicas"])
        self.kube("rollout", "status", "deployment/" + SERVICES[service], "--timeout=300s", timeout=330)

    def seeder_maintenance_start(self, operation_id):
        helper = self.journal.document["completed"].get("kube-helper")
        if helper and helper.get("seeder_operation") not in (None, operation_id):
            raise InstallError("Seeder helper belongs to another operation")
        if helper and helper.get("seeder_operation") is None:
            self.maintenance_close()
        return self.maintenance_open(seeder_operation=operation_id)

    def _ensure_maintenance_isolation(self):
        policy = self._object("NetworkPolicy", "iris-maintenance-isolation", spec={
            "podSelector": {"matchLabels": {LABEL: self.journal.document["id"], "iris.cisco.com/maintenance": "true"}},
            "policyTypes": ["Ingress", "Egress"], "ingress": [], "egress": []})
        # Persist the policy in normal ownership custody before creating a pod.
        objects = self.manifests()
        if not any(o["kind"] == "NetworkPolicy" and o["metadata"]["name"] == "iris-maintenance-isolation" for o in objects):
            atomic_write(self.manifest_file, _canonical([*objects, policy]))
            self.journal.checkpoint("kube-manifests", digest(self.manifest_file))
        self.ensure(policy)

    def seeder_maintenance_stop(self, operation_id=None):
        helper = self.journal.document["completed"].get("kube-helper")
        if helper and operation_id and helper.get("seeder_operation") not in (None, operation_id):
            raise InstallError("Seeder helper belongs to another operation")
        self.maintenance_close()

    def compose(self, *args, **kwargs):
        # Existing lifecycle engine uses a narrowly supported Compose-shaped
        # adapter contract. No CLI command strings or arbitrary remote shells.
        if args and args[0] == "build":
            return super().compose(*args, **kwargs)
        if args and args[0] == "stop":
            self.stop_writers([])
            return b""
        if args and args[0] == "up" and args[-1] in SERVICES:
            self.restart_writer({"service": args[-1]})
            return b""
        if len(args) >= 4 and args[0:2] == ("exec", "-T") and args[2] in SERVICES:
            method = self.execute if args[2] == "iris" else self.execute_console
            return method(*args[3:], **kwargs)
        if args and args[0] == "run" and "iris" in args:
            index = args.index("iris")
            if set(args[1:index]) <= {"--rm", "--no-deps", "-T"}:
                return self.maintenance_run(list(args[index + 1:]), **kwargs)
        raise InstallError("Unsupported Kubernetes lifecycle command")

    def capture_plan(self):
        self.verify_inputs()
        self.pin_runtime()
        if not all(k in self.journal.document["completed"] for k in ("prepared", "images", "packages", "kube-images")):
            raise InstallError("Complete Kubernetes installation before backup")
        sources = {name: self.base / name for name in ("source", "roots", "artifacts", "images")}
        sources.update(deployment=self.compose_file, environment=self.base / "compose.env", installation=self.journal.path,
                       **{"lifecycle-custody": self.base / "lifecycle-tls"})
        transaction = getattr(self, "credential_transaction", None)
        key = transaction.id if transaction else "backup-" + str(uuid.uuid4())
        mirror = Path("/run") / ("iris-installer-" + self.journal.document["id"]) / key
        mirror.mkdir(mode=0o700, parents=True, exist_ok=True)
        source_resources = mirror / "kubernetes-resources.json"
        resource_copy = copy.deepcopy(self.manifests())
        for resource in resource_copy:
            if resource["kind"] == "Secret" and resource["metadata"]["name"] == "iris-age":
                resource["data"] = {}
                resource["metadata"]["annotations"]["iris.cisco.com/recovery-source"] = "identity-recovery/service-identity"
        atomic_write(source_resources, _canonical(resource_copy))
        sources["kubernetes-resources"] = source_resources
        cold_mirror = self.base / "kube-snapshots" / key
        cold_mirror.mkdir(mode=0o700, parents=True, exist_ok=True)
        for member, directory in (("volume-iris-config", "config"), ("volume-iris-state", "state"), ("volume-iris-log", "log"), ("volume-iris-images", "images"), ("volume-iris-artifacts", "artifacts")):
            sources[member] = (mirror if directory in ("config", "state", "log") else cold_mirror) / directory
        containers = []
        for service in ("console", "iris"):
            current = self.get("deployment", SERVICES[service])
            containers.append({"id": current["metadata"]["uid"], "service": service, "running": current["spec"].get("replicas", 0) > 0})
        pvc = self.get("persistentvolumeclaim", "iris-data")
        return sources, {"iris-data": pvc["metadata"]["uid"]}, containers

    def capture_backup_extras(self, sources):
        from .topology_lifecycle import snapshot_tree
        self.assert_writers_stopped()
        for member, directory in (("volume-iris-config", "config"), ("volume-iris-state", "state"), ("volume-iris-log", "log"), ("volume-iris-images", "images"), ("volume-iris-artifacts", "artifacts")):
            destination = Path(sources[member])
            if destination.exists() or destination.is_symlink():
                if destination.is_symlink() or not destination.is_dir():
                    raise InstallError("Unsafe previous Kubernetes snapshot")
                destination.rename(destination.with_name(destination.name + "-retained-" + str(uuid.uuid4())))
            snapshot_tree(self.maintenance_run, "/data/" + directory, Path(sources[member]))

    def prepare_credential_sources(self, sources):
        from .topology_lifecycle import snapshot_tree
        self.assert_writers_stopped()
        destination = Path(sources["volume-iris-config"])
        if destination.exists() or destination.is_symlink():
            if destination.is_symlink() or not destination.is_dir():
                raise InstallError("Unsafe previous Kubernetes configuration snapshot")
            destination.rename(destination.with_name(destination.name + "-retained-" + str(uuid.uuid4())))
        snapshot_tree(self.maintenance_run, "/data/config", destination)

    def cleanup_snapshot_sources(self, sources):
        roots = (Path("/run") / ("iris-installer-" + self.journal.document["id"]), self.base / "kube-snapshots")
        parents = set()
        for name, path in sources.items():
            if name.startswith("volume-") or name == "kubernetes-resources":
                parent = Path(path).parent
                if parent.parent not in roots or not re.fullmatch(r"(?:backup-)?[0-9a-f-]{36}", parent.name) or parent.resolve() != parent:
                    raise InstallError("Snapshot cleanup target is outside the exact installation workspace")
                parents.add(parent)
        for parent in parents:
            if parent.exists():
                info = parent.lstat()
                if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
                    raise InstallError("Snapshot workspace custody changed")
                shutil.rmtree(parent)

    def publish_credential_file(self, path, before, payload, mode, uid, gid):
        from .topology_lifecycle import compare_write
        transaction = self.credential_transaction
        path = Path(path)
        for member, directory in (("volume-iris-config", "config"), ("volume-iris-state", "state")):
            mirror = Path(transaction.sources[member])
            if mirror in path.parents:
                compare_write(self.maintenance_run, "/data/" + directory, str(path.relative_to(mirror)), before, payload,
                              mode=mode, uid=uid, gid=gid)
                return
        if path not in (self.base / "age.txt", self.compose_file):
            raise InstallError("Credential publication is outside the approved Kubernetes roots")

    def reconcile_credential_configuration(self, transaction):
        self._recover_object_update()
        plan = transaction.directory / "write-plan.json"
        if not plan.exists():
            return
        for item in json.loads(regular_bytes(plan, 32 * 1024 * 1024)):
            if item["path"] == str(self.compose_file):
                current = digest(self.compose_file)
                if current not in (item["before"], item["after"]):
                    raise InstallError("Build projection changed outside approved credential transition")
                self.journal.checkpoint("prepared", current)

    def run_readonly(self, argv, **kwargs):
        server = self.get("deployment", SERVICES["iris"])
        if server and server["spec"].get("replicas", 0) > 0:
            return self.execute(*argv, **kwargs)
        return self.maintenance_run(argv, **kwargs)

    def finalize_credential_configuration(self, transaction):
        compose = json.loads(regular_bytes(self.compose_file))
        recipients = compose["services"]["iris"]["environment"]["IRIS_AGE_RECIPIENTS"]
        objects = self.manifests()
        env = copy.deepcopy(next(o for o in objects if o["kind"] == "ConfigMap" and o["metadata"]["name"] == "iris-seed-server"))
        if env["data"]["IRIS_AGE_RECIPIENTS"] != recipients:
            env["data"]["IRIS_AGE_RECIPIENTS"] = recipients
            self._replace_owned(env)
        identity = regular_bytes(self.base / "age.txt", 65536)
        age = copy.deepcopy(next(o for o in self.manifests() if o["kind"] == "Secret" and o["metadata"]["name"] == "iris-age"))
        if age["data"]["identity"] != base64.b64encode(identity).decode():
            age["data"]["identity"] = base64.b64encode(identity).decode()
            self._replace_owned(age)

    def management_tls_san(self):
        return "DNS:iris-server-api,DNS:iris-server-api." + self.config["kube_namespace"] + ".svc,DNS:localhost,IP:127.0.0.1"

    def before_console_start(self):
        certificate = self.python("import os; p='/run/iris/tls/management-crt.pem'; p=p if os.path.exists(p) else os.environ['IRIS_MANAGEMENT_API_CERT']; sys.stdout.buffer.write(open(p,'rb').read())")
        # Initial installations use the mounted Secret certificate; lifecycle
        # rotations use the encrypted configuration identity instead.
        ca = copy.deepcopy(next(o for o in self.manifests() if o["kind"] == "ConfigMap" and o["metadata"]["name"] == "iris-management-ca"))
        if ca["data"]["ca.crt"] != certificate.decode():
            ca["data"]["ca.crt"] = certificate.decode()
            self._replace_owned(ca)

    @property
    def service_identity_path(self):
        return "/run/secrets/age/identity"

    def sync_public_roots(self, record):
        from .deploy import read_roots
        roots = copy.deepcopy(next(o for o in self.manifests() if o["kind"] == "ConfigMap" and o["metadata"]["name"] == "iris-public-roots"))
        data = {k: v.decode() for k, v in read_roots(self.base / "roots").items()}
        if roots["data"] != data:
            roots["data"] = data
            self._replace_owned(roots)

    def maintenance_cleanup(self, transaction):
        helper = self.journal.document["completed"].get("kube-helper")
        if helper and helper.get("seeder_operation") not in (None, transaction.id):
            raise InstallError("Maintenance helper belongs to another transaction")
        self.maintenance_close()

    def seeder_maintenance_apply(self, transaction):
        from .kube_credentials import apply_seeder
        return apply_seeder(self, transaction)

    def verify_live_age(self, transaction, independent):
        from .kube_credentials import verify_live_age
        return verify_live_age(self, transaction, independent)

    def sync_management_operation(self, operation_id):
        from .management_sync import validate_operation
        approved = validate_operation(self, operation_id)
        self.pin_runtime()
        data = json.loads(self.python("import os,json,base64; from pathlib import Path; print(json.dumps({name:base64.b64encode(Path(os.environ[variable]).read_bytes() if name=='current' or Path(os.environ[variable]).exists() else b'').decode() for name,variable in [('current','IRIS_MANAGEMENT_API_TOKEN_FILE'),('previous','IRIS_MANAGEMENT_API_PREVIOUS_TOKEN_FILE')]}))"))
        pair = copy.deepcopy(next(o for o in self.manifests() if o["kind"] == "Secret" and o["metadata"]["name"] == "iris-tier-auth"))
        if pair["data"] != data:
            pair["data"] = data
            self._replace_owned(pair)
        console = copy.deepcopy(next(o for o in self.manifests() if o["kind"] == "Deployment" and o["metadata"]["name"] == SERVICES["console"]))
        annotations = console["spec"]["template"]["metadata"].setdefault("annotations", {})
        if annotations.get("iris.cisco.com/management-operation") != operation_id:
            annotations["iris.cisco.com/management-operation"] = operation_id
            self._replace_owned(console)
        self.kube("rollout", "status", "deployment/iris-console", "--timeout=300s", timeout=330)
        for pod in self._pods("console"):
            checksum = self.kube("exec", "-i", pod["name"], "-c", "console", "--", "python3", "-I", "-B", "-c",
                "import sys,os,hashlib;sys.path.insert(0,'/opt/iris/server');import tier_auth;t,_=tier_auth.load_pair(os.environ['IRIS_MANAGEMENT_API_TOKEN_FILE']);print(hashlib.sha256(t).hexdigest())", capture=True).decode().strip()
            if checksum != approved["current_sha256"]:
                raise InstallError("A Console replica has not consumed the approved management credential")
        proof = self.lifecycle_consumer_proof()
        if validate_operation(self, operation_id) != approved:
            raise InstallError("Management credential authority changed during synchronization")
        return dict(approved, consumers_verified=len(proof["console_consumers"]))

    def lifecycle_capabilities(self):
        return ["management-tls", "device-tls", "peer-ca", "instruction-roots", "age-identity", "age-recovery", "seeder-announce"]

    def backup_export_images(self, output):
        # Every runtime digest came from these already pinned local source
        # builds. Export their immutable IDs, never a mutable registry tag.
        self.command(["docker", "image", "save", "-o", output, *sorted(set(self.journal.document["completed"]["images"].values()))])

    def backup_capacity_preflight(self, sources, output, recovery):
        # PVC requested capacity is a conservative data upper bound before
        # stopping. Reserve local snapshot + encrypted data + image export.
        quantity = self.config["kube_storage_size"]
        requested = int(quantity[:-2]) * (1024 ** (3 if quantity.endswith("Gi") else 4))
        image_bytes = sum(json.loads(self.command(["docker", "image", "inspect", image], capture=True))[0]["Size"]
                          for image in set(self.journal.document["completed"]["images"].values()))
        for path, needed in ((self.base, requested * 2 + image_bytes * 2), (Path(output).parent, requested + image_bytes), (Path(recovery).parent, 1024 ** 3)):
            if shutil.disk_usage(path).free < needed + 1024 ** 3:
                raise InstallError("Insufficient backup space for Kubernetes PVC capacity and image export")
