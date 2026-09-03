# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

import os

# Imported directly, NOT via pytest.importorskip: PyYAML is a declared test
# dependency (requirements-dev.txt), and these are SECURITY assertions about
# the shipped manifests. A missing dependency must fail the run, not quietly
# subtract ten checks from it.
import yaml
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
K8S = os.path.join(ROOT, "kubernetes")


def _load(name):
    with open(os.path.join(K8S, name), encoding="utf-8") as f:
        return yaml.safe_load(f)


def test_seed_server_is_single_replica_with_recreate_strategy():
    spec = _load("deployment.yaml")["spec"]
    assert spec["replicas"] == 1
    assert spec["strategy"]["type"] == "Recreate"
    assert spec["template"]["spec"]["nodeSelector"]["kubernetes.io/arch"] == "amd64"


def test_bootstrap_init_uses_same_image_and_age_secret_as_server():
    pod = _load("deployment.yaml")["spec"]["template"]["spec"]
    init = pod["initContainers"][0]
    app = pod["containers"][0]
    assert init["image"] == app["image"]
    assert init["args"] == ["iris-bootstrap"]
    assert any(v["name"] == "age-key" for v in pod["volumes"])
    age = next(v for v in pod["volumes"] if v["name"] == "age-key")
    assert age["secret"]["secretName"] == "iris-age"


def test_plaintext_runtime_secrets_use_memory_emptydir():
    pod = _load("deployment.yaml")["spec"]["template"]["spec"]
    runtime = next(v for v in pod["volumes"] if v["name"] == "runtime-secrets")
    assert runtime["emptyDir"]["medium"] == "Memory"
    app = pod["containers"][0]
    mount = next(v for v in app["volumeMounts"] if v["name"] == "runtime-secrets")
    assert mount["mountPath"] == "/run/iris"


def test_load_balancer_preserves_sources_and_never_exposes_rpc():
    spec = _load("service.yaml")["spec"]
    assert spec["type"] == "LoadBalancer"
    assert spec["ipFamilies"] == ["IPv4"]
    assert spec["externalTrafficPolicy"] == "Local"
    ports = {p["port"] for p in spec["ports"]}
    assert ports == {6969, 8443, 8000, 6881, 8080, 9101}
    assert 6800 not in ports


def _load_env(name):
    """KEY=VALUE file consumed by kustomize configMapGenerator (envs:)."""
    data = {}
    with open(os.path.join(K8S, name), encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            key, _, value = line.partition("=")
            data[key] = value
    return data


def test_config_keeps_persistent_and_plaintext_paths_separate():
    # The ConfigMap is generated from the env file (IRIS-13-014): a plain
    # configmap.yaml resource was updated in place and never rolled the pod.
    data = _load_env("iris-seed-server.env")
    assert data["IRIS_STATE"].startswith("/data/")
    assert data["IRIS_CONFIG"].startswith("/data/")
    assert data["IRIS_SECRETS"] == "/run/iris/secrets.json"
    assert data["IRIS_RPC_SECRET_FILE"] == "/run/iris/rpc-secret"


def test_pod_satisfies_restricted_pod_security_profile():
    ns = _load("namespace.yaml")
    assert ns["metadata"]["labels"]["pod-security.kubernetes.io/enforce"] == "restricted"
    pod = _load("deployment.yaml")["spec"]["template"]["spec"]
    sc = pod["securityContext"]
    assert sc["runAsNonRoot"] is True
    # Must match the uid/gid the server image runs as; fsGroup lets that uid
    # read the 0400 age-key secret and write the PVC-backed /data volume.
    assert sc["runAsUser"] == sc["runAsGroup"] == sc["fsGroup"] == 10001
    assert sc["seccompProfile"]["type"] == "RuntimeDefault"
    for container in pod["initContainers"] + pod["containers"]:
        csc = container["securityContext"]
        assert csc["allowPrivilegeEscalation"] is False
        assert csc["capabilities"]["drop"] == ["ALL"]
    # restricted forbids host namespaces, hostPath volumes, and hostPorts.
    assert not any(pod.get(k) for k in ("hostNetwork", "hostPID", "hostIPC"))
    assert not any("hostPath" in v for v in pod["volumes"])
    for container in pod["initContainers"] + pod["containers"]:
        assert not any("hostPort" in p for p in container.get("ports", []))


def test_operator_copy_works_with_dropped_chown_capability():
    with open(os.path.join(K8S, "README.md"), encoding="utf-8") as f:
        assert "kubectl -n iris cp --no-preserve" in f.read()


def test_configmap_is_generated_so_edits_roll_the_pod():
    kust = _load("kustomization.yaml")
    assert "configmap.yaml" not in kust["resources"]
    gen = kust["configMapGenerator"][0]
    assert gen["name"] == "iris-seed-server"
    assert gen["envs"] == ["iris-seed-server.env"]
    pod = _load("deployment.yaml")["spec"]["template"]["spec"]
    for container in pod["initContainers"] + pod["containers"]:
        assert container["envFrom"][0]["configMapRef"]["name"] == "iris-seed-server"
        # mutable placeholder tag: never let a node keep a stale cached image
        assert container["imagePullPolicy"] == "Always"


def test_rollout_restart_is_documented_for_same_tag_rebuilds():
    with open(os.path.join(K8S, "README.md"), encoding="utf-8") as f:
        assert "rollout restart deployment/iris-seed-server" in f.read()
