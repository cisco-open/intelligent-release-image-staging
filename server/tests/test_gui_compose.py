# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0
import os

_SERVER = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _read(name):
    with open(os.path.join(_SERVER, name), encoding="utf-8") as f:
        return f.read()


def test_compose_publishes_gui_port():
    # shared hosts may already have :8080 taken (e.g. Jenkins) — the published
    # side is overridable via IRIS_GUI_PUBLISH, defaulting to 8080.
    assert '"${IRIS_GUI_PUBLISH:-8080}:8080"' in _read("docker-compose.yml")


def test_entrypoint_launches_and_supervises_gui():
    txt = _read("docker-entrypoint.sh")
    assert "gui_server.py" in txt
    assert "IRIS_SECRETS_ENC" in txt          # persistence target exported for the GUI
    assert 'wait -n "$T" "$C" "$S" "$A" "$G"' in txt


def test_dockerfile_exposes_gui_port():
    assert "8080" in _read("Dockerfile")


def test_compose_declares_images_volume():
    txt = _read("docker-compose.yml")
    assert "iris-images:/var/lib/iris-images" in txt      # mount
    assert "\n  iris-images:" in txt                       # named-volume declaration


def test_entrypoint_exports_images_dir():
    txt = _read("docker-entrypoint.sh")
    assert "IRIS_IMAGES_DIR" in txt


def test_seed_launch_covers_upload_dir():
    txt = _read("seed-launch.sh")
    assert "IRIS_IMAGES_DIR" in txt


def test_dockerfile_installs_ssh_deps():
    txt = _read("Dockerfile")
    assert "sshpass" in txt and "openssh-client" in txt


def test_server_image_bakes_device_and_lab_sources():
    df = _read("Dockerfile")
    assert "COPY device/ /opt/iris/device/" in df
    assert "COPY lab/ /opt/iris/lab/" in df
    txt = _read("docker-compose.yml")
    assert ":/opt/iris/device" not in txt
    assert ":/opt/iris/lab" not in txt


def test_compose_builds_self_contained_image_from_repo_root():
    import yaml
    build = yaml.safe_load(_read("docker-compose.yml"))["services"]["iris"]["build"]
    assert build["context"] == ".."
    assert build["dockerfile"] == "server/Dockerfile"


def test_compose_artifacts_is_read_write_for_self_provisioning():
    # The container self-provisions the derivable served files at startup
    # (provision-served.sh: rebuilds iris-agent.tgz, copies bootstrap.sh,
    # refreshes iris-catalog.pem), so the artifacts mount must be read-WRITE.
    import yaml
    svc = yaml.safe_load(_read("docker-compose.yml"))["services"]["iris"]
    volumes = svc["volumes"]
    assert any(v.endswith(":/srv/artifacts") for v in volumes)
    assert not any(v.endswith(":/srv/artifacts:ro") for v in volumes)


def test_compose_drops_redundant_staging_submount():
    # with the whole artifacts mount read-write, the separate staging sub-bind
    # (the old workaround for a read-only parent) is redundant — staging is
    # just a writable subdir the entrypoint mkdirs.
    txt = _read("docker-compose.yml")
    assert "../artifacts/staging:/srv/artifacts/staging" not in txt


def test_entrypoint_self_provisions_served_artifacts():
    # the fresh-deploy fix: the entrypoint stages the Guest Shell bundle,
    # bootstrap.sh and iris-catalog.pem so onboarding doesn't fail on an empty
    # artifacts/ dir.
    assert "provision-served.sh" in _read("docker-entrypoint.sh")


def test_entrypoint_creates_writable_staging_dir():
    txt = _read("docker-entrypoint.sh")
    assert 'mkdir -p "${IRIS_ARTIFACTS_DIR:-/srv/artifacts}/staging"' in txt


def test_dockerfile_exposes_artifacts_seed_data_and_healthcheck():
    df = _read("Dockerfile")
    assert "EXPOSE 6969 8443 8000 6881 8080 9101" in df
    assert "EXPOSE 6800" not in df
    assert "HEALTHCHECK" in df and "9101/healthz" in df


def test_dockerfile_rejects_non_amd64_server_builds():
    df = _read("Dockerfile")
    assert "TARGETARCH" in df
    assert "supports linux/amd64 only" in df


def test_dockerfile_uses_emulation_safe_go_crypto_for_age():
    assert "GODEBUG=cpu.all=off" in _read("Dockerfile")


def test_compose_declares_runtime_secret_paths_for_exec_commands():
    import yaml
    env = yaml.safe_load(_read("docker-compose.yml"))["services"]["iris"]["environment"]
    assert env["IRIS_RPC_SECRET_FILE"] == "/run/iris/rpc-secret"
    assert env["IRIS_SECRETS"] == "/run/iris/secrets.json"


def test_version_baked_as_optional_build_arg():
    # Dockerfile takes an OPTIONAL build arg (empty default — no new required
    # vars) and exposes it as env for gui_server._read_version.
    df = _read("Dockerfile")
    assert "ARG IRIS_VERSION=" in df
    assert "ENV IRIS_VERSION=${IRIS_VERSION}" in df


def test_compose_forwards_version_build_arg():
    import yaml
    svc = yaml.safe_load(_read("docker-compose.yml"))["services"]["iris"]
    # build-time arg with an EMPTY default (":-") so `docker compose up`
    # without IRIS_VERSION still builds; Settings then shows "unknown".
    assert svc["build"]["args"]["IRIS_VERSION"] == "${IRIS_VERSION:-}"
    # must live under build.args, NOT the runtime environment mapping — a
    # runtime entry would override the image-baked value with "" on restarts.
    assert "IRIS_VERSION" not in svc.get("environment", {})
