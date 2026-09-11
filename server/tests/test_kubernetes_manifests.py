# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Static security and topology assertions for the shipped Kubernetes base.

The suite deliberately needs only PyYAML.  It catches unsafe source changes in
CI without requiring a Kubernetes cluster, registry credentials, or a local
kustomize binary.
"""

import os
import re

# Imported directly, NOT via pytest.importorskip: PyYAML is a declared test
# dependency (requirements-dev.txt), and these are security assertions. A
# missing dependency must fail the run, not silently subtract checks from it.
import yaml


ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
# The override is used only by the regression test procedure: run this current
# suite against a scratch copy of the previous manifests and prove they fail.
K8S = os.environ.get("IRIS_K8S_TEST_ROOT", os.path.join(ROOT, "kubernetes"))


def _load(name):
    with open(os.path.join(K8S, name), encoding="utf-8") as stream:
        return yaml.safe_load(stream)


def _load_all(name):
    with open(os.path.join(K8S, name), encoding="utf-8") as stream:
        return [doc for doc in yaml.safe_load_all(stream) if doc]


def _pod(deployment):
    return deployment["spec"]["template"]["spec"]


def _all_containers(pod):
    return pod.get("initContainers", []) + pod["containers"]


def _env(container):
    return {item["name"]: item["value"] for item in container.get("env", [])}


def _volume(pod, name):
    return next(volume for volume in pod["volumes"] if volume["name"] == name)


def _mount(container, name):
    return next(mount for mount in container["volumeMounts"] if mount["name"] == name)


def _load_env(name):
    """Load a KEY=VALUE file consumed by kustomize configMapGenerator."""
    data = {}
    with open(os.path.join(K8S, name), encoding="utf-8") as stream:
        for raw_line in stream:
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            key, separator, value = line.partition("=")
            assert separator, f"invalid env line in {name}: {raw_line!r}"
            data[key] = value
    return data


def test_server_and_console_are_independent_single_replica_deployments():
    server = _load("deployment.yaml")
    console = _load("console-deployment.yaml")

    for deployment, name, component in (
        (server, "iris-seed-server", "server"),
        (console, "iris-console", "console"),
    ):
        assert deployment["spec"]["replicas"] == 1
        assert deployment["spec"]["strategy"]["type"] == "Recreate"
        assert deployment["spec"]["selector"]["matchLabels"] == {
            "app.kubernetes.io/name": name
        }
        labels = deployment["spec"]["template"]["metadata"]["labels"]
        assert labels["app.kubernetes.io/name"] == name
        assert labels["app.kubernetes.io/component"] == component
        assert labels["app.kubernetes.io/part-of"] == "iris"
        assert _pod(deployment)["nodeSelector"]["kubernetes.io/arch"] == "amd64"

    console_container = _pod(console)["containers"][0]
    assert console_container["command"] == [
        "python3",
        "/opt/iris/server/gui_server.py",
    ]


def test_bootstrap_init_uses_same_image_and_age_secret_as_server():
    pod = _pod(_load("deployment.yaml"))
    init = pod["initContainers"][0]
    app = pod["containers"][0]
    assert init["image"] == app["image"]
    assert init["args"] == ["iris-bootstrap"]
    age = _volume(pod, "age-key")
    assert age["secret"]["secretName"] == "iris-age"


def test_only_server_mounts_the_existing_rwo_data_claim():
    server_pod = _pod(_load("deployment.yaml"))
    console_pod = _pod(_load("console-deployment.yaml"))
    pvc = _load("pvc.yaml")

    assert pvc["metadata"]["name"] == "iris-data"
    assert pvc["spec"]["accessModes"] == ["ReadWriteOnce"]
    data = _volume(server_pod, "data")
    assert data["persistentVolumeClaim"]["claimName"] == "iris-data"
    assert _mount(server_pod["containers"][0], "data")["mountPath"] == "/data"
    assert not any("persistentVolumeClaim" in volume for volume in console_pod["volumes"])
    assert not any(
        mount["mountPath"] == "/data"
        for container in _all_containers(console_pod)
        for mount in container.get("volumeMounts", [])
    )


def test_plaintext_runtime_material_uses_per_tier_memory_emptydirs():
    server_pod = _pod(_load("deployment.yaml"))
    console_pod = _pod(_load("console-deployment.yaml"))

    assert _volume(server_pod, "runtime-secrets")["emptyDir"]["medium"] == "Memory"
    assert _mount(server_pod["containers"][0], "runtime-secrets")["mountPath"] == "/run/iris"
    assert _volume(console_pod, "runtime")["emptyDir"]["medium"] == "Memory"
    assert _mount(console_pod["containers"][0], "runtime")["mountPath"] == "/run/iris"


def test_external_and_internal_service_surfaces_are_separate():
    server = _load("service.yaml")["spec"]
    console = _load("console-service.yaml")["spec"]
    management = _load("management-service.yaml")["spec"]

    assert server["type"] == console["type"] == "LoadBalancer"
    assert server["ipFamilies"] == console["ipFamilies"] == ["IPv4"]
    assert server["externalTrafficPolicy"] == "Local"
    assert {port["port"] for port in server["ports"]} == {
        6969,
        8443,
        8000,
        6881,
        9101,
    }
    assert {port["port"] for port in console["ports"]} == {8080}
    assert management["type"] == "ClusterIP"
    assert {port["port"] for port in management["ports"]} == {9443}
    externally_exposed = {
        port["port"] for service in (server, console) for port in service["ports"]
    }
    assert 6800 not in externally_exposed
    assert 9443 not in externally_exposed


def test_network_policy_allows_management_api_only_from_console():
    policies = {doc["metadata"]["name"]: doc for doc in _load_all("network-policy.yaml")}
    assert set(policies) == {
        "iris-default-deny-ingress",
        "iris-server-ingress",
        "iris-console-ingress",
    }
    deny = policies["iris-default-deny-ingress"]["spec"]
    assert deny["policyTypes"] == ["Ingress"]
    assert deny["ingress"] == []

    server = policies["iris-server-ingress"]["spec"]
    public_rule, management_rule = server["ingress"]
    assert {port["port"] for port in public_rule["ports"]} == {
        6969,
        8443,
        8000,
        6881,
        9101,
    }
    assert "from" not in public_rule
    assert {port["port"] for port in management_rule["ports"]} == {9443}
    assert management_rule["from"] == [
        {
            "podSelector": {
                "matchLabels": {
                    "app.kubernetes.io/name": "iris-console",
                    "app.kubernetes.io/component": "console",
                }
            }
        }
    ]

    console = policies["iris-console-ingress"]["spec"]
    assert {port["port"] for port in console["ingress"][0]["ports"]} == {8080}
    for policy in policies.values():
        assert "Egress" not in policy["spec"]["policyTypes"]


def test_tier_auth_and_tls_material_are_mounted_by_least_privilege():
    server_pod = _pod(_load("deployment.yaml"))
    console_pod = _pod(_load("console-deployment.yaml"))
    server = server_pod["containers"][0]
    console = console_pod["containers"][0]

    for pod in (server_pod, console_pod):
        tier_auth = _volume(pod, "tier-auth")["secret"]
        assert tier_auth["secretName"] == "iris-tier-auth"
        assert {item["key"] for item in tier_auth["items"]} == {"current", "previous"}

    management_tls = _volume(server_pod, "management-tls")["secret"]
    assert management_tls["secretName"] == "iris-management-tls"
    assert {item["key"] for item in management_tls["items"]} == {"tls.crt", "tls.key"}
    assert not any(volume["name"] == "management-tls" for volume in console_pod["volumes"])

    management_ca = _volume(console_pod, "management-ca")["configMap"]
    assert management_ca["name"] == "iris-management-ca"
    assert {item["key"] for item in management_ca["items"]} == {"ca.crt"}
    assert not any(volume["name"] == "management-ca" for volume in server_pod["volumes"])

    server_env = _env(server)
    console_env = _env(console)
    for env in (server_env, console_env):
        assert env["IRIS_MANAGEMENT_API_TOKEN_FILE"].endswith("/current")
        assert env["IRIS_MANAGEMENT_API_PREVIOUS_TOKEN_FILE"].endswith("/previous")
    assert server_env["IRIS_MANAGEMENT_API_CERT"].endswith("/tls.crt")
    assert server_env["IRIS_MANAGEMENT_API_KEY"].endswith("/tls.key")
    assert "IRIS_MANAGEMENT_API_CA" not in server_env
    assert console_env["IRIS_MANAGEMENT_API_CA"].endswith("/ca.crt")
    assert "IRIS_MANAGEMENT_API_CERT" not in console_env
    assert "IRIS_MANAGEMENT_API_KEY" not in console_env
    assert console_env["IRIS_GUI_CERT"] == "/run/iris/console-cert.pem"

    console_tls = _volume(console_pod, "console-tls")["secret"]
    assert console_tls["secretName"] == "iris-console-tls"
    assert console_tls["defaultMode"] == 0o440
    assert {item["key"] for item in console_tls["items"]} == {"tls.crt", "tls.key"}
    console_tls_mount = _mount(console, "console-tls")
    assert console_tls_mount == {
        "name": "console-tls",
        "mountPath": "/run/secrets/iris-console-tls",
        "readOnly": True,
    }
    assert console_env["IRIS_GUI_DEFAULT_CERT"] == (
        "/run/secrets/iris-console-tls/tls.crt"
    )
    assert console_env["IRIS_GUI_DEFAULT_KEY"] == (
        "/run/secrets/iris-console-tls/tls.key"
    )
    assert not any(volume["name"] == "console-tls" for volume in server_pod["volumes"])


def test_observability_auth_is_a_separate_server_only_rotation_pair():
    server_pod = _pod(_load("deployment.yaml"))
    console_pod = _pod(_load("console-deployment.yaml"))
    server = server_pod["containers"][0]
    console = console_pod["containers"][0]

    secret = _volume(server_pod, "observability-auth")["secret"]
    assert secret["secretName"] == "iris-observability-auth"
    assert secret["defaultMode"] == 0o440
    assert {item["key"] for item in secret["items"]} == {"current", "previous"}
    assert _mount(server, "observability-auth") == {
        "name": "observability-auth",
        "mountPath": "/run/secrets/iris-observability-auth",
        "readOnly": True,
    }

    server_env = _env(server)
    assert server_env["IRIS_OBSERVABILITY_TOKEN_FILE"] == (
        "/run/secrets/iris-observability-auth/current"
    )
    assert server_env["IRIS_OBSERVABILITY_PREVIOUS_TOKEN_FILE"] == (
        "/run/secrets/iris-observability-auth/previous"
    )
    assert "IRIS_OBSERVABILITY_TOKEN_FILE" not in _env(console)
    assert "IRIS_OBSERVABILITY_PREVIOUS_TOKEN_FILE" not in _env(console)
    assert not any(
        volume["name"] == "observability-auth" for volume in console_pod["volumes"]
    )


def test_otlp_collector_headers_are_an_optional_server_only_secret():
    server_pod = _pod(_load("deployment.yaml"))
    console_pod = _pod(_load("console-deployment.yaml"))
    server = server_pod["containers"][0]
    console = console_pod["containers"][0]

    secret = _volume(server_pod, "otlp-headers")["secret"]
    assert secret == {
        "secretName": "iris-otlp-headers",
        "defaultMode": 0o440,
        "optional": True,
        "items": [{"key": "headers", "path": "headers"}],
    }
    assert _mount(server, "otlp-headers") == {
        "name": "otlp-headers",
        "mountPath": "/run/secrets/iris-otlp-headers",
        "readOnly": True,
    }
    assert _env(server)["IRIS_OTLP_HEADERS_FILE"] == (
        "/run/secrets/iris-otlp-headers/headers"
    )
    assert "IRIS_OTLP_HEADERS" not in _env(console)
    assert "IRIS_OTLP_HEADERS_FILE" not in _env(console)
    assert not any(
        volume["name"] == "otlp-headers" for volume in console_pod["volumes"]
    )


def test_default_first_run_has_no_setup_token_projection():
    server_pod = _pod(_load("deployment.yaml"))
    console_pod = _pod(_load("console-deployment.yaml"))
    server = server_pod["containers"][0]
    console = console_pod["containers"][0]

    for pod, container in ((server_pod, server), (console_pod, console)):
        assert "IRIS_CONSOLE_SETUP_TOKEN_FILE" not in _env(container)
        assert not any(
            volume["name"] == "console-setup" for volume in pod["volumes"])
        assert not any(
            mount["name"] == "console-setup"
            for mount in container.get("volumeMounts", []))


def test_probes_are_per_tier_and_do_not_create_cold_start_dependency():
    server = _pod(_load("deployment.yaml"))["containers"][0]
    console = _pod(_load("console-deployment.yaml"))["containers"][0]

    for container in (server, console):
        assert container["startupProbe"]["httpGet"]["path"] == "/readyz"
        assert container["readinessProbe"]["httpGet"]["path"] == "/readyz"
        assert container["livenessProbe"]["httpGet"]["path"] == "/healthz"
    for container in (server, console):
        for probe in ("startupProbe", "readinessProbe", "livenessProbe"):
            # Even anonymous non-disclosing probes stay encrypted; this also
            # prevents the authenticated metrics bearer from ever sharing a
            # plaintext external listener.
            assert container[probe]["httpGet"]["scheme"] == "HTTPS"

    listeners = _load_env("iris-seed-server.env")["IRIS_HEALTH_LISTENERS"]
    assert listeners == (
        "tracker:6969,catalog:8443,artifacts:8000,management-api:9443"
    )
    assert "console" not in listeners


def test_both_pods_satisfy_restricted_pod_security_profile():
    namespace = _load("namespace.yaml")
    assert namespace["metadata"]["labels"]["pod-security.kubernetes.io/enforce"] == "restricted"

    for deployment_name in ("deployment.yaml", "console-deployment.yaml"):
        pod = _pod(_load(deployment_name))
        security = pod["securityContext"]
        assert security["runAsNonRoot"] is True
        assert security["runAsUser"] == security["runAsGroup"] == security["fsGroup"] == 10001
        assert security["seccompProfile"]["type"] == "RuntimeDefault"
        for container in _all_containers(pod):
            container_security = container["securityContext"]
            assert container_security["allowPrivilegeEscalation"] is False
            assert container_security["capabilities"]["drop"] == ["ALL"]
        assert not any(pod.get(key) for key in ("hostNetwork", "hostPID", "hostIPC"))
        assert not any("hostPath" in volume for volume in pod["volumes"])
        for container in _all_containers(pod):
            assert not any("hostPort" in port for port in container.get("ports", []))


def test_server_pvc_remount_preserves_private_authority_file_modes():
    security = _pod(_load("deployment.yaml"))["securityContext"]
    # With the documented PVC root already prepared, kubelet must leave the
    # 0600 authority locks/transcripts untouched. Always (including omission)
    # adds group write on remount and makes the strict authority readers fail.
    assert security.get("fsGroupChangePolicy") == "OnRootMismatch"


def test_every_container_has_explicit_resource_requests_and_limits():
    for deployment_name in ("deployment.yaml", "console-deployment.yaml"):
        for container in _all_containers(_pod(_load(deployment_name))):
            resources = container["resources"]
            assert set(resources["requests"]) == {"cpu", "memory"}
            assert set(resources["limits"]) == {"cpu", "memory"}


def test_each_tier_uses_a_content_hashed_generated_configmap():
    kustomization = _load("kustomization.yaml")
    generators = {item["name"]: item for item in kustomization["configMapGenerator"]}
    assert generators == {
        "iris-seed-server": {
            "name": "iris-seed-server",
            "envs": ["iris-seed-server.env"],
        },
        "iris-console": {"name": "iris-console", "envs": ["iris-console.env"]},
    }
    assert not kustomization.get("generatorOptions", {}).get("disableNameSuffixHash", False)

    for deployment_name, config_name in (
        ("deployment.yaml", "iris-seed-server"),
        ("console-deployment.yaml", "iris-console"),
    ):
        for container in _all_containers(_pod(_load(deployment_name))):
            assert container["envFrom"][0]["configMapRef"]["name"] == config_name

    with open(os.path.join(ROOT, ".gitignore"), encoding="utf-8") as stream:
        assert "!kubernetes/iris-console.env" in stream.read().splitlines()


def test_server_and_console_images_are_separate_immutable_fail_closed_placeholders():
    server_pod = _pod(_load("deployment.yaml"))
    console_pod = _pod(_load("console-deployment.yaml"))
    image_pattern = re.compile(r"^iris-(server|console)@sha256:[0-9a-f]{64}$")

    server_images = {container["image"] for container in _all_containers(server_pod)}
    console_images = {container["image"] for container in _all_containers(console_pod)}
    assert len(server_images) == len(console_images) == 1
    assert server_images.isdisjoint(console_images)
    for pod in (server_pod, console_pod):
        for container in _all_containers(pod):
            assert image_pattern.fullmatch(container["image"])
            assert container["imagePullPolicy"] == "IfNotPresent"

    images = {item["name"]: item for item in _load("kustomization.yaml")["images"]}
    assert set(images) == {"iris-server", "iris-console"}
    for image in images.values():
        assert image["newName"].startswith("registry.example.invalid/")
        assert re.fullmatch(r"sha256:[0-9a-f]{64}", image["digest"])
        assert image["digest"] == "sha256:" + ("0" * 64)
        assert "newTag" not in image


def test_persistent_and_runtime_config_paths_remain_separate():
    server = _load_env("iris-seed-server.env")
    console = _load_env("iris-console.env")

    assert server["IRIS_STATE"].startswith("/data/")
    assert server["IRIS_CONFIG"].startswith("/data/")
    assert server["IRIS_SECRETS"] == "/run/iris/secrets.json"
    assert server["IRIS_RPC_SECRET_FILE"] == "/run/iris/rpc-secret"
    assert server["IRIS_MANAGEMENT_API_PORT"] == "9443"
    assert console["IRIS_MANAGEMENT_API_URL"] == "https://iris-server-api:9443"
    assert not any("TOKEN" in key or "SECRET" in key for key in console)


def test_operator_readme_documents_split_topology_and_safe_copy():
    with open(os.path.join(K8S, "README.md"), encoding="utf-8") as stream:
        readme = stream.read()

    assert "| `iris-seed-server` | `LoadBalancer` | `6969, 8443, 8000, 6881, 9101` |" in readme
    assert "| `iris-console` | `LoadBalancer` | `8080` |" in readme
    assert "| `iris-server-api` | `ClusterIP` | `9443` |" in readme
    assert "kubectl -n iris cp --no-preserve" in readme
    assert "current" in readme and "previous" in readme
    assert "/readyz" in readme and "/healthz" in readme
    assert "iris-console-tls" in readme
    assert "subjectAltName" in readme
    assert "exact DNS name or IP address" in readme
    assert "iris-observability-auth" in readme
    assert "iris-otlp-headers" in readme
    assert "iris-console-setup" not in readme
    assert "There is no shared default Console password" not in readme
    assert "`iris` / `irisisgreat!`" in readme
    assert "openssl rand -hex 32 > iris-observability-auth/current" in readme
    assert "credentials_file:" in readme
    assert "ca_file:" in readme
    assert "scheme: https" in readme
    assert "neither raw value is" in readme
    assert "accepted by the management API" in readme
