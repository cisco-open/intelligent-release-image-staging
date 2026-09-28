# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Kubernetes installer ownership, isolation and recovery contract tests."""

import copy
import hashlib
import json
from pathlib import Path
import sys
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools"))
from iris_installer import kube_deploy as kube
from iris_installer.state import InstallError, atomic_write


def config(**changes):
    return dict(dict(target="kubernetes", instance="iris-test", host="192.0.2.10",
        console_bind="192.0.2.11", console_port=28080, peer_tls="required", recovery_recipient="age1" + "q" * 58,
        kubeconfig_path="/etc/iris/kubeconfig", kube_context="lab", kube_namespace="iris-test", kube_storage_class="storage",
        kube_storage_size="20Gi", kube_registry="", kube_registry_auth="", kube_console_replicas=2,
        kube_image_import="k3s", kube_node="lab-node", lifecycle_url="https://192.0.2.20:28443"), **changes)


@pytest.mark.parametrize("changes", [
    {"kube_namespace": "default"}, {"kube_namespace": "kube-system"}, {"kube_namespace": "-bad"},
    {"kube_context": "-bad"}, {"kube_context": "a;id"}, {"kubeconfig_path": "relative"},
    {"kube_storage_class": ""}, {"kube_storage_size": "0Gi"}, {"kube_storage_size": "20G"},
    {"kube_console_replicas": True}, {"kube_console_replicas": 0}, {"kube_console_replicas": 9},
    {"kube_image_import": "command"}, {"kube_image_import": "registry"}, {"kube_node": ""},
    {"kube_registry": "https://registry/x"}, {"kube_registry": "user:pass@registry/x"},
    {"kube_registry_auth": "/etc/iris/auth"}, {"lifecycle_url": "http://192.0.2.10"}, {"extra": "x"},
])
def test_rejects_ambiguous_or_unsafe_configuration(changes):
    with pytest.raises(InstallError):
        kube.validate_kube_config(config(**changes))


def test_accepts_explicit_registry_or_local_import():
    kube.validate_kube_config(config())
    kube.validate_kube_config(config(kube_image_import="registry", kube_node="", kube_registry="registry.example/iris"))


def test_api_omitted_empty_policy_lists_remain_deny_all():
    expected = {'kind': 'NetworkPolicy', 'spec': {'podSelector': {},
        'policyTypes': ['Ingress', 'Egress'], 'ingress': [], 'egress': []}}
    actual = copy.deepcopy(expected)
    actual['spec'].pop('ingress')
    actual['spec'].pop('egress')
    assert kube._contains(actual, expected)
    actual['spec']['egress'] = [{}]
    assert not kube._contains(actual, expected)
    actual['spec'].pop('egress')
    actual['spec']['policyTypes'] = ['Ingress']
    assert not kube._contains(actual, expected)


def install(tmp_path):
    obj = object.__new__(kube.KubeInstall)
    obj.base = tmp_path
    obj.source = Path(__file__).resolve().parents[2]
    obj.config = config()
    obj.manifest_file = tmp_path / "kube.json"
    obj.compose_file = tmp_path / "compose.json"
    obj.env = {}
    doc = {"id": "3cc14a5c-1212-4455-bb99-daaeaeccbbaa", "config": obj.config,
           "completed": {"kube-images": {"iris": "registry/iris@sha256:" + "a" * 64, "console": "registry/console@sha256:" + "b" * 64}}}
    obj.journal = SimpleNamespace(document=doc, directory=tmp_path, save=lambda: None,
        checkpoint=lambda key, value: doc["completed"].update({key: value}))
    obj.cluster_preflight = lambda: None
    obj.kube = lambda *args, **kwargs: b'{"items": []}'
    return obj


@pytest.mark.parametrize("phase", ["preparing", "overlap-active", "secret-published", "new-client-verified", "renewing-expired"])
def test_install_resume_requires_explicit_pending_transport_recovery(tmp_path, phase):
    obj = install(tmp_path)
    authority = {"instance_id": obj.journal.document["id"], "phase": phase}
    atomic_write(tmp_path / "lifecycle-transport-operation.json", json.dumps(authority).encode())
    obj.verify_inputs = lambda: pytest.fail("ordinary resume bypassed pending connection recovery")
    with pytest.raises(InstallError, match="connection certificate operation"):
        obj.resume()


def test_completed_transport_does_not_block_install_resume(tmp_path):
    obj = install(tmp_path)
    authority = {"instance_id": obj.journal.document["id"], "phase": "complete"}
    atomic_write(tmp_path / "lifecycle-transport-operation.json", json.dumps(authority).encode())
    def reached_inputs():
        raise RuntimeError("normal input validation reached")
    obj.verify_inputs = reached_inputs
    with pytest.raises(RuntimeError, match="normal input validation reached"):
        obj.resume()


def manifest(obj, desired, uid="owned-uid"):
    atomic_write(obj.manifest_file, kube._canonical([desired]))
    obj.journal.document["completed"]["kube-manifests"] = kube.digest(obj.manifest_file)
    key = desired["kind"] + "/" + desired["metadata"]["name"]
    obj.journal.document["completed"]["kube-resources"] = {key: {"uid": uid, "sha256": hashlib.sha256(kube._canonical(desired)).hexdigest()}}
    actual = copy.deepcopy(desired)
    actual["metadata"].update(uid=uid, resourceVersion="17")
    return actual


def test_pods_keep_server_identity_storage_and_lifecycle_off_console(tmp_path):
    obj = install(tmp_path)
    server, console = obj._pod_spec("iris"), obj._pod_spec("console")
    assert server["securityContext"]["runAsUser"] == 10001
    assert server["automountServiceAccountToken"] is False
    assert server["terminationGracePeriodSeconds"] == 180
    assert server["containers"][0]["image"].endswith("a" * 64)
    assert server["containers"][0]["imagePullPolicy"] == "Never"
    assert server["nodeSelector"]["kubernetes.io/hostname"] == "lab-node"
    assert "iris-bootstrap" in server["initContainers"][0]["args"][0]
    assert not any("hostPath" in volume for volume in server["volumes"] + console["volumes"])
    console_secrets = {volume["secret"]["secretName"] for volume in console["volumes"] if "secret" in volume}
    assert console_secrets == {"iris-tier-auth", "iris-console-tls"}
    assert not any("persistentVolumeClaim" in volume for volume in console["volumes"])


@pytest.mark.parametrize("field,value", [("command", ["evil"]), ("args", ["evil"]),
    ("env", [{"name": "LD_PRELOAD", "value": "evil"}]), ("lifecycle", {"postStart": {}})])
def test_rejects_added_container_execution_fields(tmp_path, field, value):
    obj = install(tmp_path)
    desired = obj._object("Pod", "test", spec=obj._pod_spec("console"))
    actual = copy.deepcopy(desired)
    actual["spec"]["containers"][0][field] = value
    assert not kube._contains(actual, desired)


@pytest.mark.parametrize("kind", ["Secret", "ConfigMap"])
def test_rejects_extra_secret_or_environment_data(tmp_path, kind):
    obj = install(tmp_path)
    desired = obj._object(kind, "test", data={"known": "value"})
    actual = copy.deepcopy(desired)
    actual["data"]["IRIS_EVIL"] = "injected"
    assert not kube._contains(actual, desired)


def test_no_adoption_even_with_matching_resource_bytes(tmp_path):
    obj = install(tmp_path)
    desired = obj._object("ConfigMap", "test", data={"x": "y"})
    obj.get = lambda *args: desired
    with pytest.raises(InstallError, match="refusing adoption"):
        obj.ensure(desired)


def test_durable_create_intent_can_finish_after_response_loss(tmp_path):
    obj = install(tmp_path)
    desired = obj._object("ConfigMap", "test", data={"x": "y"})
    actual = manifest(obj, desired, uid=None)
    actual["metadata"]["uid"] = "created-by-us"
    obj.get = lambda *args: actual
    obj.ensure(desired)
    assert obj.journal.document["completed"]["kube-resources"]["ConfigMap/test"]["uid"] == "created-by-us"


def test_replacement_uid_refused_even_matching_labels(tmp_path):
    obj = install(tmp_path)
    desired = obj._object("ConfigMap", "test", data={"x": "y"})
    actual = manifest(obj, desired)
    actual["metadata"]["uid"] = "replacement"
    obj.get = lambda *args: actual
    with pytest.raises(InstallError, match="UID changed"):
        obj.ensure(desired)


def test_update_uses_uid_and_resource_version_compare_and_swap(tmp_path):
    obj = install(tmp_path)
    old = obj._object("ConfigMap", "test", data={"x": "old"})
    current = manifest(obj, old)
    obj.get = lambda *args: current
    calls = []
    def command(*args, **kwargs):
        calls.append((args, kwargs))
        return kwargs["input"]
    obj.kube = command
    new = copy.deepcopy(old)
    new["data"]["x"] = "new"
    obj._replace_owned(new)
    sent = json.loads(calls[0][1]["input"])
    assert sent["metadata"]["uid"] == "owned-uid"
    assert sent["metadata"]["resourceVersion"] == "17"
    assert not (tmp_path / "kube-update.json").exists()
    assert obj.manifests()[0]["data"] == {"x": "new"}


def test_readonly_pin_recognizes_applied_pending_update_without_repair(tmp_path):
    obj = install(tmp_path)
    old = obj._object("ConfigMap", "test", data={"x": "old"})
    manifest(obj, old)
    new = obj._object("ConfigMap", "test", data={"x": "new"})
    actual = copy.deepcopy(new)
    actual["metadata"].update(uid="owned-uid", resourceVersion="18")
    obj.get = lambda *args: actual
    atomic_write(tmp_path / "kube-update.json", kube._canonical({"before": old, "after": new, "uid": "owned-uid"}))
    before_bytes = obj.manifest_file.read_bytes()
    obj.pin_runtime()
    assert obj.manifest_file.read_bytes() == before_bytes
    obj._recover_object_update()
    assert obj.manifests()[0] == new


def test_pending_update_rejects_unapproved_remote_content(tmp_path):
    obj = install(tmp_path)
    old = obj._object("ConfigMap", "test", data={"x": "old"})
    actual = manifest(obj, old)
    new = obj._object("ConfigMap", "test", data={"x": "new"})
    actual["data"]["x"] = "other"
    obj.get = lambda *args: actual
    atomic_write(tmp_path / "kube-update.json", kube._canonical({"before": old, "after": new, "uid": "owned-uid"}))
    with pytest.raises(InstallError):
        obj.pin_runtime()


def test_console_proof_covers_every_replica_and_pins_uid_set(tmp_path):
    obj = install(tmp_path)
    pods = [{"name": "console-1", "uid": "uid-1"}, {"name": "console-2", "uid": "uid-2"}]
    obj._pods = lambda service: pods
    obj.get = lambda kind, name: {"metadata": {"uid": next(p["uid"] for p in pods if p["name"] == name)}}
    calls = []
    obj.kube = lambda *args, **kwargs: calls.append(args) or json.dumps({"management_https": "verified", "certificate_sha256": "a" * 64}).encode()
    proof = obj.lifecycle_consumer_proof()
    assert len(calls) == 2
    assert {p["pod_uid"] for p in proof["console_consumers"]} == {"uid-1", "uid-2"}


def test_replica_fingerprint_disagreement_fails_closed(tmp_path):
    obj = install(tmp_path)
    pods = [{"name": "console-1", "uid": "uid-1"}, {"name": "console-2", "uid": "uid-2"}]
    obj._pods = lambda service: pods
    obj.get = lambda kind, name: {"metadata": {"uid": next(p["uid"] for p in pods if p["name"] == name)}}
    values = iter(["a" * 64, "b" * 64])
    obj.kube = lambda *args, **kwargs: json.dumps({"management_https": "verified", "certificate_sha256": next(values)}).encode()
    with pytest.raises(InstallError, match="different management"):
        obj.lifecycle_consumer_proof()


def test_maintenance_close_uses_uid_delete_precondition(tmp_path):
    obj = install(tmp_path)
    obj.journal.document["completed"]["kube-helper"] = {"name": "helper", "uid": "owned"}
    obj.get = lambda *args: {"metadata": {"uid": "owned"}}
    calls = []
    obj.kube = lambda *args, **kwargs: calls.append((args, kwargs)) or b""
    obj.maintenance_close()
    assert calls[0][0][0:2] == ("delete", "--raw")
    assert json.loads(calls[0][1]["input"])["preconditions"] == {"uid": "owned"}


def test_arbitrary_compose_command_is_never_forwarded(tmp_path):
    obj = install(tmp_path)
    with pytest.raises(InstallError, match="Unsupported"):
        obj.compose("run", "--privileged", "iris", "sh")


def test_snapshot_cleanup_rejects_other_installation_path(tmp_path):
    obj = install(tmp_path)
    with pytest.raises(InstallError, match="outside"):
        obj.cleanup_snapshot_sources({"volume-iris-config": tmp_path / "user-data/config"})


def test_manifests_keep_private_roots_off_cluster_and_state_off_console(tmp_path, monkeypatch):
    obj = install(tmp_path)
    (tmp_path / "roots").mkdir()
    (tmp_path / "roots/root-a.pub").write_text("ssh-ed25519 AAAAfirst public\n")
    (tmp_path / "roots/root-b.pub").write_text("ssh-ed25519 AAAAsecond public\n")
    (tmp_path / "age.txt").write_bytes(b"service-identity")
    custody = {}
    for name in ("ca.crt", "client.crt", "client.key"):
        custody[name] = tmp_path / name
        custody[name].write_bytes(name.encode())
    from iris_installer import lifecycle_network
    monkeypatch.setattr(lifecycle_network, "prepare_network_custody", lambda *args: custody)
    obj._certificate = lambda *args: {"tls.key": b"key", "tls.crt": b"certificate"}
    obj.command = lambda *args, **kwargs: ("age1" + "q" * 58).encode()
    objects = obj.manifests()
    indexed = {(o["kind"], o["metadata"]["name"]): o for o in objects}
    assert indexed["Deployment", "iris-seed-server"]["spec"]["replicas"] == 1
    assert indexed["Deployment", "iris-console"]["spec"]["replicas"] == 2
    assert set(indexed["Secret", "iris-lifecycle"]["data"]) == {"ca.crt", "client.crt", "client.key"}
    assert set(indexed["ConfigMap", "iris-public-roots"]["data"]) == {"root-a.pub", "root-b.pub"}
    assert indexed["Service", "iris-server-api"]["spec"].get("type", "ClusterIP") == "ClusterIP"
    assert indexed["Service", "iris-console"]["spec"]["loadBalancerIP"] == "192.0.2.11"
    env = indexed["ConfigMap", "iris-seed-server"]["data"]
    assert env["IRIS_MANAGEMENT_API_TOKEN_FILE"] == "/data/config/tier/current.json"
    assert env["IRIS_INSTALLER_SHUTDOWN_PROOF"] == "/data/state/installer-shutdown.json"
    assert obj.manifests() == objects


def test_registry_pods_reference_explicit_pull_secret(tmp_path):
    obj = install(tmp_path)
    obj.config.update(kube_image_import="registry", kube_node="", kube_registry="registry.example/iris", kube_registry_auth="/etc/auth.json")
    for service in ("iris", "console"):
        pod = obj._pod_spec(service)
        assert pod["imagePullSecrets"] == [{"name": "iris-registry"}]
        assert pod["containers"][0]["imagePullPolicy"] == "IfNotPresent"


def test_unowned_allow_policy_cannot_silently_broaden_isolation(tmp_path):
    obj = install(tmp_path)
    desired = obj._object("ConfigMap", "test", data={"x": "y"})
    current = manifest(obj, desired)
    obj.get = lambda *args: current
    obj.kube = lambda *args, **kwargs: b'{"items":[{"metadata":{"name":"allow-everything"}}]}'
    with pytest.raises(InstallError, match="NetworkPolicy"):
        obj.verify_resource_ownership()


def test_helper_create_crash_recovers_only_exact_durable_intent(tmp_path):
    obj = install(tmp_path)
    obj.assert_writers_stopped = lambda: None
    obj._ensure_maintenance_isolation = lambda: None
    current = None
    obj.get = lambda *args: current
    def command(*args, **kwargs):
        nonlocal current
        if args[0] == "create":
            current = json.loads(kwargs["input"])
            current["metadata"]["uid"] = "created-helper"
            raise InstallError("response lost")
        return b""
    obj.kube = command
    with pytest.raises(InstallError, match="response lost"):
        obj.maintenance_open()
    assert obj.journal.document["completed"]["kube-helper"]["uid"] is None
    name = obj.maintenance_open()
    assert name == current["metadata"]["name"]
    assert obj.journal.document["completed"]["kube-helper"]["uid"] == "created-helper"


def test_helper_exec_refuses_same_uid_with_substituted_image(tmp_path):
    obj = install(tmp_path)
    obj.assert_writers_stopped = lambda: None
    desired = obj._object("Pod", "helper", spec=obj._pod_spec("iris"))
    atomic_write(tmp_path / "kube-helper.json", kube._canonical(desired))
    obj.journal.document["completed"]["kube-helper"] = {"name": "helper", "uid": "same-uid", "sha256": kube.digest(tmp_path / "kube-helper.json")}
    actual = copy.deepcopy(desired)
    actual["metadata"]["uid"] = "same-uid"
    actual["spec"]["containers"][0]["image"] = "attacker:latest"
    obj.get = lambda *args: actual
    with pytest.raises(InstallError):
        obj.maintenance_run(["python3", "-V"])


def test_failed_new_writer_can_be_stopped_for_same_transaction_recovery(tmp_path):
    obj = install(tmp_path)
    obj.pin_runtime = lambda: None
    obj.get = lambda *args: {"spec": {"replicas": 1}}
    obj.credential_transaction = SimpleNamespace(record={"initial_clean_stop": True, "mutations_admitted": True})
    obj._pods = lambda *args: pytest.fail("recovery must not require a ready failed writer")
    obj.assert_writers_stopped = lambda: None
    obj.maintenance_open = lambda: None
    scaled = []
    obj.scale = lambda *args: scaled.append(args)
    obj.stop_writers([])
    assert scaled == [("console", 0), ("iris", 0)]


def test_initial_backup_refuses_unready_writer_without_clean_authority(tmp_path):
    obj = install(tmp_path)
    obj.pin_runtime = lambda: None
    obj.get = lambda *args: {"spec": {"replicas": 1}}
    obj._pods = lambda *args: (_ for _ in ()).throw(InstallError("not ready"))
    obj.scale = lambda *args: pytest.fail("no initial clean authority")
    with pytest.raises(InstallError, match="not ready"):
        obj.stop_writers([])


def test_external_service_address_must_match_requested_ip(tmp_path):
    obj = install(tmp_path)
    obj.get = lambda *args: {"status": {"loadBalancer": {"ingress": [{"ip": "192.0.2.99"}]}}}
    with pytest.raises(InstallError, match="exact requested"):
        obj.verify_external_services(b"unused certificate")


def test_pending_manifest_write_before_checkpoint_is_recoverable(tmp_path):
    obj = install(tmp_path)
    old = obj._object("ConfigMap", "test", data={"x": "old"})
    manifest(obj, old)
    new = obj._object("ConfigMap", "test", data={"x": "new"})
    atomic_write(obj.manifest_file, kube._canonical([new]))
    actual = copy.deepcopy(new)
    actual["metadata"].update(uid="owned-uid", resourceVersion="18")
    obj.get = lambda *args: actual
    atomic_write(tmp_path / "kube-update.json", kube._canonical({"before": old, "after": new, "uid": "owned-uid"}))
    obj.pin_runtime()
    obj._recover_object_update()
    assert obj.manifests() == [new]
