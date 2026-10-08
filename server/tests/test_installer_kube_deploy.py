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


@pytest.mark.parametrize("kind", ["Pod", "Deployment"])
def test_api_omitted_empty_env_literal_preserves_exact_execution_intent(kind):
    spec = {"containers": [{"name": "iris", "env": [{"name": "IRIS_INSTALLER_SHUTDOWN_PROOF", "value": ""}]}]}
    expected = {"kind": kind, "spec": spec if kind == "Pod" else {"template": {"spec": spec}}}
    actual = copy.deepcopy(expected)
    actual_spec = actual["spec"] if kind == "Pod" else actual["spec"]["template"]["spec"]
    entry = actual_spec["containers"][0]["env"][0]
    del entry["value"]
    assert kube._contains(actual, expected)
    assert "value" not in entry  # normalization never changes observed input
    entry["valueFrom"] = {"secretKeyRef": {"name": "unapproved", "key": "value"}}
    assert not kube._contains(actual, expected)
    del entry["valueFrom"]
    entry["value"] = "enabled"
    assert not kube._contains(actual, expected)
    entry["value"] = ""
    actual_spec["containers"][0]["env"].append({"name": "EXTRA", "value": "unexpected"})
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
    for pod in (server, console):
        env = {item["name"]: item for item in pod["containers"][0]["env"]}
        for name, field in (("IRIS_POD_NAME", "metadata.name"),
                            ("IRIS_POD_NAMESPACE", "metadata.namespace"),
                            ("IRIS_NODE_NAME", "spec.nodeName"),
                            ("IRIS_POD_IP", "status.podIP")):
            assert env[name]["valueFrom"]["fieldRef"] == {"apiVersion": "v1", "fieldPath": field}


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


@pytest.mark.parametrize("matches", [True, False])
def test_management_replacement_token_is_proved_in_same_https_probe(tmp_path, matches):
    obj = install(tmp_path)
    pods = [{"name": "console-1", "uid": "uid-1", "container_id": "containerd://first"}]
    obj._pods = lambda service: pods
    obj.get = lambda *args: {"metadata": {"uid": "uid-1"}}
    def execute(*args, **kwargs):
        assert args[-1] == "b" * 64
        code = args[-2]
        assert "token_sha256=hashlib.sha256(t).hexdigest()" in code
        assert "'Authorization':'Bearer '+t.decode()" in code
        return json.dumps({"management_https": "verified", "certificate_sha256": "a" * 64,
                           "current_sha256": "b" * 64 if matches else "c" * 64}).encode()
    obj.kube = execute
    if matches:
        assert obj.lifecycle_consumer_proof(expected_token="b" * 64)["console_consumers"][0]["current_sha256"] == "b" * 64
    else:
        with pytest.raises(InstallError, match="approved management credential"):
            obj.lifecycle_consumer_proof(expected_token="b" * 64)


def test_same_pod_container_restart_invalidates_consumer_proof(tmp_path):
    obj = install(tmp_path)
    before = [{"name": "console-1", "uid": "uid-1", "container_id": "containerd://first"}]
    after = [{"name": "console-1", "uid": "uid-1", "container_id": "containerd://second"}]
    snapshots = iter((before, after))
    obj._pods = lambda service: next(snapshots)
    obj.get = lambda *args: {"metadata": {"uid": "uid-1"}}
    obj.kube = lambda *args, **kwargs: json.dumps({"management_https": "verified", "certificate_sha256": "a" * 64}).encode()
    with pytest.raises(InstallError, match="replicas changed"):
        obj.lifecycle_consumer_proof()


@pytest.mark.parametrize("same_operation", [True, False])
def test_scheduled_management_sync_recovers_only_its_exact_pending_manifest(tmp_path, same_operation):
    obj = install(tmp_path)
    identifier = "33eaaec9-a7e8-42bc-a425-c746518ced40"
    approved = {"request_id": identifier, "current_sha256": "b" * 64}
    old = obj._secret("iris-tier-auth", {"current": b"old", "previous": b""})
    manifest(obj, old)
    new = obj._secret("iris-tier-auth", {"current": b"new", "previous": b"old"})
    new["metadata"].pop("annotations", None)
    new["metadata"]["annotations"] = {kube.INTENT: hashlib.sha256(kube._canonical(new)).hexdigest()}
    actual = copy.deepcopy(new)
    actual["metadata"].update(uid="owned-uid", resourceVersion="18")
    obj.get = lambda *args: actual
    atomic_write(obj.manifest_file, kube._canonical([new]))
    atomic_write(tmp_path / "kube-update.json", kube._canonical({"before": old, "after": new, "uid": "owned-uid"}))
    authority = dict(approved, instance_id=obj.journal.document["id"], mutation_sha256=hashlib.sha256(kube._canonical(new)).hexdigest())
    if not same_operation:
        authority["request_id"] = "555a8520-6d70-423c-b681-cf410af27e2c"
    atomic_write(tmp_path / "management-sync.json", kube._canonical(authority))
    obj._pods = lambda *args, **kwargs: [{"name": "server", "uid": "server-uid", "container_id": "server-incarnation"}]
    obj.kube = lambda *args, **kwargs: json.dumps(approved if args[0] == "exec" else {"items": []}).encode()
    obj.python = lambda *args: json.dumps(approved).encode()
    def recovered():
        assert not (tmp_path / "kube-update.json").exists()
        assert obj.manifests() == [new]
        raise RuntimeError("recovered checkpoint")
    obj.pin_runtime = recovered
    if same_operation:
        with pytest.raises(RuntimeError, match="recovered checkpoint"):
            obj.sync_management_operation(identifier)
    else:
        with pytest.raises(InstallError, match="not approved by this management operation"):
            obj.sync_management_operation(identifier)
        assert (tmp_path / "kube-update.json").exists()


def test_management_sync_journals_scoped_intent_before_each_publication(tmp_path):
    obj = install(tmp_path)
    identifier = "33eaaec9-a7e8-42bc-a425-c746518ced40"
    approved = {"request_id": identifier, "current_sha256": "b" * 64}
    data = {"current": "bmV3", "previous": "b2xk"}
    replies = iter((approved, data, approved))
    obj.python = lambda *args: json.dumps(next(replies)).encode()
    obj.pin_runtime = lambda: None
    objects = [obj._secret("iris-tier-auth", {"current": b"old", "previous": b""}),
               obj._object("Deployment", "iris-console", spec={"template": {"metadata": {}}})]
    obj.manifests = lambda: copy.deepcopy(objects)
    published = []
    def replace(desired):
        record = json.loads((tmp_path / "management-sync.json").read_bytes())
        assert record["request_id"] == identifier and record["current_sha256"] == approved["current_sha256"]
        normalized = copy.deepcopy(desired)
        normalized["metadata"].pop("annotations", None)
        normalized["metadata"]["annotations"] = {kube.INTENT: hashlib.sha256(kube._canonical(normalized)).hexdigest()}
        assert record["mutation_sha256"] == hashlib.sha256(kube._canonical(normalized)).hexdigest()
        published.append(desired["kind"])
    obj._replace_owned = replace
    def consumers(*, expected_token):
        assert expected_token == approved["current_sha256"]
        return {"console_consumers": [{"pod_uid": "one"}, {"pod_uid": "two"}]}
    obj.lifecycle_consumer_proof = consumers
    assert obj.sync_management_operation(identifier) == dict(approved, consumers_verified=2)
    assert published == ["Secret", "Deployment"]


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


@pytest.mark.parametrize("seeder_operation", [None, "33eaaec9-a7e8-42bc-a425-c746518ced40"])
def test_helper_create_crash_recovers_only_exact_durable_intent(tmp_path, seeder_operation):
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
            if seeder_operation:
                for entry in current["spec"]["containers"][0]["env"]:
                    if entry.get("value") == "":
                        entry.pop("value")
            raise InstallError("response lost")
        return b""
    obj.kube = command
    with pytest.raises(InstallError, match="response lost"):
        obj.maintenance_open(seeder_operation=seeder_operation)
    assert obj.journal.document["completed"]["kube-helper"]["uid"] is None
    name = obj.maintenance_open(seeder_operation=seeder_operation)
    assert name == current["metadata"]["name"]
    assert obj.journal.document["completed"]["kube-helper"]["uid"] == "created-helper"
    container = current["spec"]["containers"][0]
    if seeder_operation:
        assert container["command"] == ["/opt/iris/server/docker-entrypoint.sh"]
        assert container["readinessProbe"]["exec"]["command"] == ["test", "-f", "/run/iris/maintenance-ready"]
        assert not {"startupProbe", "livenessProbe"}.intersection(container)
    else:
        assert container["command"] == ["python3", "-I", "-B", "-c", kube.MAINTENANCE_IDLE, "/run/iris/instr"]
    assert current["spec"]["restartPolicy"] == "Never"


@pytest.mark.parametrize("signal_name", ["SIGTERM", "SIGINT"])
def test_actual_idle_helper_command_exits_cleanly_on_shutdown(tmp_path, signal_name):
    import signal
    import subprocess
    import time
    runtime = tmp_path / "runtime-instr"
    # The packaged code and arguments are unchanged except the fixed runtime
    # directory, relocated into this unprivileged test's private workspace.
    process = subprocess.Popen([sys.executable, "-I", "-B", "-c", kube.MAINTENANCE_IDLE, str(runtime)],
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        deadline = time.monotonic() + 5
        while not runtime.is_dir():
            assert process.poll() is None and time.monotonic() < deadline
            time.sleep(.01)
        assert runtime.stat().st_mode & 0o777 == 0o700
        process.send_signal(getattr(signal, signal_name))
        stdout, stderr = process.communicate(timeout=2)
        assert process.returncode == 0
        assert stdout == stderr == b""
    finally:
        if process.poll() is None:
            process.kill()
            process.communicate(timeout=2)


def test_helper_exec_refuses_same_uid_with_substituted_image(tmp_path):
    obj = install(tmp_path)
    obj.assert_writers_stopped = lambda **kwargs: None
    obj._maintenance_read_view = lambda helper: {}
    desired = obj._object("Pod", "helper", spec=obj._pod_spec("iris"))
    atomic_write(tmp_path / "kube-helper.json", kube._canonical(desired))
    obj.journal.document["completed"]["kube-helper"] = {"name": "helper", "uid": "same-uid", "sha256": kube.digest(tmp_path / "kube-helper.json")}
    actual = copy.deepcopy(desired)
    actual["metadata"]["uid"] = "same-uid"
    actual["spec"]["containers"][0]["image"] = "attacker:latest"
    obj.get = lambda *args, **kwargs: actual
    with pytest.raises(InstallError):
        obj.maintenance_run(["python3", "-V"])


def bulk_maintenance(tmp_path):
    obj = install(tmp_path)
    desired = [obj._object("Namespace", obj.config["kube_namespace"]),
        *[obj._object("Deployment", name, spec={"replicas": 0, "template": {"spec": obj._pod_spec(service)}})
          for service, name in kube.SERVICES.items()],
        obj._object("ConfigMap", "settings", data={"setting": "owned"}),
        obj._secret("secret", {"value": b"private"}),
        obj._object("NetworkPolicy", "deny", spec={"podSelector": {}, "policyTypes": ["Ingress"], "ingress": []})]
    atomic_write(obj.manifest_file, kube._canonical(desired))
    completed = obj.journal.document["completed"]
    completed["kube-manifests"] = kube.digest(obj.manifest_file)
    completed["kube-cluster"] = {"uid": "cluster-uid", "server": "https://cluster", "context": "lab"}
    completed["kube-resources"] = {}
    explicit, policies = [], []
    for intent in desired:
        actual = copy.deepcopy(intent)
        actual["metadata"].update(uid="uid-" + intent["metadata"]["name"], resourceVersion="1")
        (policies if intent["kind"] == "NetworkPolicy" else explicit).append(actual)
        completed["kube-resources"][intent["kind"] + "/" + intent["metadata"]["name"]] = {
            "uid": actual["metadata"]["uid"], "sha256": hashlib.sha256(kube._canonical(intent)).hexdigest()}
    explicit.extend([{"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": "kube-system", "uid": "cluster-uid"}},
        {"apiVersion": "storage.k8s.io/v1", "kind": "StorageClass", "metadata": {"name": "storage", "uid": "storage-uid"}}])
    helper = obj._object("Pod", "helper", spec={"containers": [{"name": "iris", "image": "owned@sha256:" + "a" * 64}],
        "volumes": [{"name": "data", "persistentVolumeClaim": {"claimName": "iris-data"}}]})
    atomic_write(tmp_path / "kube-helper.json", kube._canonical(helper))
    completed["kube-helper"] = {"name": "helper", "uid": "helper-uid", "sha256": kube.digest(tmp_path / "kube-helper.json")}
    helper = copy.deepcopy(helper)
    helper["metadata"]["uid"] = "helper-uid"
    helper["status"] = {"containerStatuses": [{"name": "iris", "containerID": "containerd://first",
        "restartCount": 0, "state": {"running": {"startedAt": "2026-09-28T12:00:00Z"}}}]}
    state = {"explicit": explicit, "namespace": [helper, *policies], "fresh_helper": helper, "calls": [], "preflights": 0}
    def preflight():
        state["preflights"] += 1
    obj.cluster_preflight = preflight
    def command(*args, **kwargs):
        state["calls"].append(args)
        if args[0] == "exec":
            return b"checked"
        if args[:2] == ("get", "pods,networkpolicies"):
            assert "-l" not in args and "--selector" not in args
            result = {"apiVersion": "v1", "kind": "List", "items": state["namespace"]}
        elif args[:3] == ("get", "pod", "helper"):
            result = state["fresh_helper"]
        else:
            assert args[0] == "get" and all("/" in ref for ref in args[1:-4])
            result = {"apiVersion": "v1", "kind": "List", "items": state["explicit"]}
        return json.dumps(result).encode()
    obj.kube = command
    return obj, state


def test_bulk_maintenance_fence_refreshes_every_call_and_keeps_preflight(tmp_path):
    obj, state = bulk_maintenance(tmp_path)
    assert obj.maintenance_run(["python3", "-V"], capture=True) == b"checked"
    assert obj.maintenance_run(["python3", "-V"], capture=True) == b"checked"
    assert state["preflights"] == 2
    assert len(state["calls"]) == 8  # two lists, fresh helper, exec per call
    view = obj._maintenance_read_view(obj.journal.document["completed"]["kube-helper"])
    assert obj.get("deployment", "iris-console", read_view=view) == obj.get("Deployment", "iris-console", read_view=view)
    with pytest.raises(InstallError, match="does not cover"):
        obj.get("Secret", "unrequested", read_view=view)


@pytest.mark.parametrize("fault", ["missing", "duplicate", "namespace", "unexpected", "api", "cluster", "uid", "spec", "foreign-writer", "foreign-policy", "helper-restart", "helper-uid", "helper-namespace", "duplicate-pod", "missing-helper"])
def test_bulk_maintenance_refuses_drift_before_exec(tmp_path, fault):
    obj, state = bulk_maintenance(tmp_path)
    if fault == "missing":
        state["explicit"].pop()
    elif fault == "duplicate":
        state["explicit"].append(copy.deepcopy(state["explicit"][0]))
    elif fault == "namespace":
        state["explicit"][1]["metadata"]["namespace"] = "other"
    elif fault == "unexpected":
        extra = copy.deepcopy(state["explicit"][3])
        extra["metadata"]["name"] = "unrequested"
        state["explicit"].append(extra)
    elif fault == "api":
        state["explicit"][1]["apiVersion"] = "foreign/v1"
    elif fault == "cluster":
        next(row for row in state["explicit"] if row["metadata"]["name"] == "kube-system")["metadata"]["uid"] = "another-cluster"
    elif fault == "uid":
        state["explicit"][1]["metadata"]["uid"] = "replacement"
    elif fault == "spec":
        state["explicit"][3]["data"]["setting"] = "changed"
    elif fault in ("foreign-writer", "foreign-policy"):
        extra = copy.deepcopy(state["namespace"][0 if fault == "foreign-writer" else 1])
        extra["metadata"].update(name="foreign", uid="foreign-uid")
        state["namespace"].append(extra)
    elif fault == "helper-restart":
        state["fresh_helper"] = copy.deepcopy(state["fresh_helper"])
        state["fresh_helper"]["status"]["containerStatuses"][0]["containerID"] = "containerd://restarted"
    elif fault == "helper-uid":
        state["fresh_helper"] = copy.deepcopy(state["fresh_helper"])
        state["fresh_helper"]["metadata"]["uid"] = "replacement-helper"
    elif fault == "helper-namespace":
        state["namespace"][0]["metadata"]["namespace"] = "another"
    elif fault == "duplicate-pod":
        state["namespace"].append(copy.deepcopy(state["namespace"][0]))
    elif fault == "missing-helper":
        state["namespace"].pop(0)
    with pytest.raises(InstallError):
        obj.maintenance_run(["python3", "-V"])
    assert not any(call[0] == "exec" for call in state["calls"])


@pytest.mark.parametrize("approved", [True, False])
def test_bulk_fence_preserves_exact_pending_before_after_authority(tmp_path, approved):
    obj, state = bulk_maintenance(tmp_path)
    objects = json.loads(obj.manifest_file.read_bytes())
    before = next(row for row in objects if row["kind"] == "ConfigMap")
    after = obj._object("ConfigMap", "settings", data={"setting": "approved"})
    actual = next(row for row in state["explicit"] if row["kind"] == "ConfigMap")
    actual["data"] = after["data"] if approved else {"setting": "unapproved"}
    actual["metadata"]["annotations"] = after["metadata"]["annotations"]
    objects[objects.index(before)] = after
    atomic_write(obj.manifest_file, kube._canonical(objects))
    atomic_write(tmp_path / "kube-update.json", kube._canonical({"before": before, "after": after, "uid": actual["metadata"]["uid"]}))
    authority_bytes = (tmp_path / "kube-update.json").read_bytes()
    if approved:
        assert obj.maintenance_run(["python3", "-V"]) == b"checked"
    else:
        with pytest.raises(InstallError, match="pending update ownership changed"):
            obj.maintenance_run(["python3", "-V"])
    assert (tmp_path / "kube-update.json").read_bytes() == authority_bytes


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


@pytest.mark.parametrize("active", [0, 2])
def test_external_seeder_listener_only_required_for_actual_active_torrents(tmp_path, active):
    obj = install(tmp_path)
    obj.get = lambda kind, service: {"status": {"loadBalancer": {"ingress": [{"ip": obj.config["host"] if service == "iris-seed-server" else obj.config["console_bind"]}]}}}
    obj.execute = lambda *args, **kwargs: b"device certificate"
    obj.seeder_readiness = lambda: {"rpc": "verified", "active_torrents": active}
    endpoints = []
    obj._verify_external_endpoint = lambda *args: endpoints.append(args)
    obj.verify_external_services(b"console certificate")
    assert [row[2] for row in endpoints] == [6969, 8443, 8000, 9101, 28080] + ([6881] if active else [])
    proof = obj.journal.document["completed"]["kube-external-services"]["seeder"]
    assert proof == {"rpc": "verified", "active_torrents": active,
                     "peer_listener": "verified" if active else "idle-no-active-torrents"}


@pytest.mark.parametrize("report", [{"rpc": "verified", "active_torrents": True}, {"rpc": "verified", "active_torrents": -1}, {"rpc": "failed", "active_torrents": 0}, {}])
def test_seeder_readiness_requires_explicit_valid_authenticated_rpc_evidence(tmp_path, report):
    obj = install(tmp_path)
    obj.execute = lambda *args, **kwargs: json.dumps(report).encode()
    with pytest.raises(InstallError, match="Authenticated local seeder RPC"):
        obj.seeder_readiness()


def test_external_endpoint_retries_transient_service_propagation(tmp_path, monkeypatch):
    from contextlib import nullcontext
    obj = install(tmp_path)
    attempts = []
    def connect(address, timeout):
        attempts.append(address)
        if len(attempts) == 1:
            raise ConnectionRefusedError("private exception details")
        return nullcontext()
    monkeypatch.setattr(kube.socket, "create_connection", connect)
    monkeypatch.setattr(kube.time, "sleep", lambda duration: None)
    obj._verify_external_endpoint("BitTorrent seeder", "192.0.2.10", 6881)
    assert attempts == [("192.0.2.10", 6881)] * 2


def test_external_endpoint_failure_names_endpoint_without_exception_details(tmp_path, monkeypatch):
    obj = install(tmp_path)
    ticks = iter((0, 31))
    monkeypatch.setattr(kube.time, "monotonic", lambda: next(ticks))
    def connect(*args, **kwargs):
        raise TimeoutError("private exception details")
    monkeypatch.setattr(kube.socket, "create_connection", connect)
    with pytest.raises(InstallError, match="External catalog at 192.0.2.10:8443.*connection timed out") as failure:
        obj._verify_external_endpoint("catalog", "192.0.2.10", 8443)
    assert "private exception details" not in str(failure.value)


@pytest.mark.parametrize("matches", [True, False])
def test_external_tls_probe_requires_hostname_and_exact_owned_certificate(tmp_path, monkeypatch, matches):
    from contextlib import nullcontext
    obj = install(tmp_path)
    secured = SimpleNamespace(getpeercert=lambda **kwargs: b"owned" if matches else b"other")
    calls = []
    def wrap(sock, server_hostname):
        calls.append(server_hostname)
        return nullcontext(secured)
    def context(*, cadata):
        assert cadata == "owned public PEM"
        return SimpleNamespace(wrap_socket=wrap)
    monkeypatch.setattr(kube.ssl, "create_default_context", context)
    monkeypatch.setattr(kube.ssl, "PEM_cert_to_DER_cert", lambda pem: b"owned")
    monkeypatch.setattr(kube.socket, "create_connection", lambda *args, **kwargs: nullcontext("socket"))
    ticks = iter((0, 31))
    monkeypatch.setattr(kube.time, "monotonic", lambda: next(ticks))
    if matches:
        obj._verify_external_endpoint("catalog", "192.0.2.10", 8443, b"owned public PEM")
    else:
        with pytest.raises(InstallError, match="catalog at 192.0.2.10:8443.*TLS certificate"):
            obj._verify_external_endpoint("catalog", "192.0.2.10", 8443, b"owned public PEM")
    assert calls == ["192.0.2.10"]


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
