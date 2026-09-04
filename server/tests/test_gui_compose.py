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
    import yaml
    services = yaml.safe_load(_read("docker-compose.yml"))["services"]
    assert '"${IRIS_GUI_PUBLISH:-8080}:8080"' in _read("docker-compose.yml")
    assert services["console"]["ports"] == ["${IRIS_GUI_PUBLISH:-8080}:8080"]
    assert not any(str(p).endswith(":8080")
                   for p in services["iris"].get("ports", []))


def test_entrypoint_launches_and_supervises_management_not_console():
    txt = _read("docker-entrypoint.sh")
    assert "python3 management_api.py & M=$!" in txt
    assert "python3 gui_server.py" not in txt
    assert "IRIS_SECRETS_ENC" in txt
    assert 'wait -n "$T" "$C" "$S" "$A" "$M"' in txt


def test_console_has_its_own_minimal_image_and_port():
    server = _read("Dockerfile")
    console = _read("Dockerfile.console")
    assert "EXPOSE 8080" not in server
    assert "EXPOSE 8080" in console
    assert "COPY server/webroot/" in console
    assert "gui_server.py" in console
    assert "COPY device/" not in console and "COPY lab/" not in console
    assert "/opt/iris/server/iris-gui" in server


def test_console_image_has_independent_local_readiness_healthcheck():
    console = _read("Dockerfile.console")
    assert "HEALTHCHECK" in console
    assert "127.0.0.1:%s/readyz" in console
    assert "IRIS_GUI_PORT" in console
    # The probe is local, follows the exact public-listener plaintext opt-in,
    # and tolerates the TLS identity's self-signed or non-loopback SAN;
    # /readyz itself checks only local files, not backend IO.
    assert "_create_unverified_context" in console
    assert 'IRIS_GUI_ALLOW_PLAINTEXT")=="1"' in console
    assert 's="http" if' in console
    assert "IRIS_MANAGEMENT_API_URL" not in next(
        line for line in console.splitlines() if "urlopen" in line)


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
    services = yaml.safe_load(_read("docker-compose.yml"))["services"]
    assert services["iris"]["build"]["context"] == ".."
    assert services["iris"]["build"]["dockerfile"] == "server/Dockerfile"
    assert services["console"]["build"]["context"] == ".."
    assert services["console"]["build"]["dockerfile"] == \
        "server/Dockerfile.console"


def test_default_setup_has_no_deployment_token_plumbing():
    import yaml
    doc = yaml.safe_load(_read("docker-compose.yml"))
    server = doc["services"]["iris"]
    console = doc["services"]["console"]
    for service in (server, console):
        assert "IRIS_CONSOLE_SETUP_TOKEN_SOURCE" not in service["environment"]
        assert "IRIS_CONSOLE_SETUP_TOKEN_FILE" not in service["environment"]
        assert "iris_console_setup_token" not in service.get("secrets", [])
    assert "iris_console_setup_token" not in doc.get("secrets", {})
    entrypoint = _read("docker-entrypoint.sh")
    assert "IRIS_CONSOLE_SETUP_TOKEN" not in entrypoint
    assert "console-setup-token" not in entrypoint


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
    # The guarantee is that staging/ is created under a DEFAULTED artifacts
    # path, not that a particular line spells the default inline. The entrypoint
    # exports the default first and then creates the directory, so both halves
    # are asserted. Two later duplicate mkdirs were removed as redundant: the
    # export below already applies the /srv/artifacts default, and nothing
    # between them (only provision-served.sh, which creates) removes the dir.
    assert 'export IRIS_ARTIFACTS_DIR="${IRIS_ARTIFACTS_DIR:-/srv/artifacts}"' in txt
    assert 'mkdir -p "$IRIS_ARTIFACTS_DIR/staging"' in txt


def test_dockerfile_exposes_artifacts_seed_data_and_healthcheck():
    df = _read("Dockerfile")
    assert "EXPOSE 6969 8443 8000 6881 9101 9443" in df
    assert "8080" not in next(line for line in df.splitlines()
                              if line.startswith("EXPOSE "))
    assert "EXPOSE 6800" not in df
    # /readyz, not /healthz: the latter is unconditional and let a container
    # with a dead catalog/artifact listener stay `healthy` (IRIS-13-012).
    assert "HEALTHCHECK" in df and "9101/readyz" in df
    assert "https://$IRIS_HOST_IP:9101/readyz" in df
    assert "--cacert /etc/iris/tls/crt.pem" in df
    assert "9101/healthz" not in df


def test_telemetry_ca_uses_the_persisted_public_certificate():
    entrypoint = _read("docker-entrypoint.sh")
    assert 'IRIS_TELEMETRY_CA="${IRIS_TELEMETRY_CA:-$IRIS_CONFIG/tls/crt.pem}"' \
        in entrypoint
    assert "$IRIS_RUN/tls/crt.pem" not in entrypoint


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


def test_dockerfile_runs_as_nonroot_fixed_uid():
    # every listener binds >1024 and nothing needs root, so the image drops to
    # an unprivileged user. The uid is FIXED (10001) so host-side chowns of
    # bind mounts / the age key are deterministic across hosts, and fresh
    # named volumes inherit a known owner.
    df = _read("Dockerfile")
    assert "--uid 10001" in df and "--gid 10001" in df
    assert "\nUSER iris\n" in df
    # USER must take effect before the ENTRYPOINT so the entrypoint and every
    # service it supervises run unprivileged
    assert df.index("\nUSER iris\n") < df.index("ENTRYPOINT")


def test_compose_hardens_iris_service():
    import yaml
    services = yaml.safe_load(_read("docker-compose.yml"))["services"]
    for name in ("iris", "console"):
        svc = services[name]
        assert svc["user"] == "10001:10001"
        assert svc["cap_drop"] == ["ALL"]
        assert "no-new-privileges:true" in svc["security_opt"]


def test_console_has_only_tier_material_and_runtime_tmpfs():
    import yaml
    services = yaml.safe_load(_read("docker-compose.yml"))["services"]
    console = services["console"]
    mounts = "\n".join(console.get("volumes", []))
    assert "iris-tier-auth:/run/iris-tier:ro" in mounts
    assert "iris-management-ca:/run/iris-management-ca:ro" in mounts
    assert "iris-state" not in mounts
    assert "iris-config" not in mounts
    assert "iris-images" not in mounts
    assert "/srv/artifacts" not in mounts
    assert any("/run/iris-console" in item for item in console["tmpfs"])
    env = console["environment"]
    assert env["IRIS_MANAGEMENT_API_URL"] == "https://iris:9443"
    assert env["IRIS_GUI_ALLOW_PLAINTEXT"] == \
        "${IRIS_GUI_ALLOW_PLAINTEXT:-}"


def test_compose_mounts_optional_otlp_headers_only_in_server():
    import yaml
    services = yaml.safe_load(_read("docker-compose.yml"))["services"]
    server = services["iris"]
    console = services["console"]
    assert server["environment"]["IRIS_OTLP_HEADERS_FILE"] == \
        "/run/secrets/iris_otlp_headers"
    mount = next(v for v in server["volumes"]
                 if v.endswith(":/run/secrets/iris_otlp_headers:ro"))
    assert mount.startswith("${IRIS_OTLP_HEADERS_FILE_HOST:-/dev/null}")
    assert not any("iris_otlp_headers" in v
                   for v in console.get("volumes", []))
    assert "IRIS_OTLP_HEADERS_FILE" not in console["environment"]


def test_entrypoint_normalizes_absent_optional_secret_bind_files():
    entrypoint = _read("docker-entrypoint.sh")
    assert '[ ! -f "$IRIS_OBSERVABILITY_PREVIOUS_TOKEN_FILE" ]' in entrypoint
    assert 'export IRIS_OBSERVABILITY_PREVIOUS_TOKEN_FILE=""' in entrypoint
    assert '[ ! -f "$IRIS_OTLP_HEADERS_FILE" ]' in entrypoint
    assert 'export IRIS_OTLP_HEADERS_FILE=""' in entrypoint


def test_compose_forwards_version_build_arg():
    import yaml
    svc = yaml.safe_load(_read("docker-compose.yml"))["services"]["iris"]
    # build-time arg with an EMPTY default (":-") so `docker compose up`
    # without IRIS_VERSION still builds; Settings then shows "unknown".
    assert svc["build"]["args"]["IRIS_VERSION"] == "${IRIS_VERSION:-}"
    # must live under build.args, NOT the runtime environment mapping — a
    # runtime entry would override the image-baked value with "" on restarts.
    assert "IRIS_VERSION" not in svc.get("environment", {})


def test_compose_restores_the_licensed_font_by_bind_mount_only():
    """#87: .dockerignore keeps the Cisco-licensed Sharp Sans typeface out of
    the build context (so it can never enter an image layer or the release
    tarball -- see test_dockerignore.py / test_make_release.bats), but a
    deployment that independently holds the license must still be able to
    restore it at runtime. The only sanctioned path is a Compose bind mount
    -- never re-adding the file to the build context."""
    import yaml
    svc = yaml.safe_load(_read("docker-compose.yml"))["services"]["console"]
    mounts = [v for v in svc["volumes"] if "SharpSans-Bold.woff2" in v]
    assert len(mounts) == 1, "expected exactly one Sharp Sans bind mount"
    mount = mounts[0]
    # the exact runtime path server/gui_server.py's WEBROOT resolves to
    # inside the image (WORKDIR /opt/iris; COPY server/ /opt/iris/server/)
    assert mount.endswith(
        ":/opt/iris/server/webroot/fonts/SharpSans-Bold.woff2:ro"), mount
    # driven by an env var, not a literal host path baked into the file —
    # an operator without the license must get a safe no-op, not a broken
    # `docker compose up` (a missing literal host path would fail the mount)
    assert mount.startswith("${IRIS_SHARP_SANS_FONT_HOST:-"), mount
    # the default source (between ":-" and the closing "}") must be a path
    # virtually guaranteed to exist on any Linux Compose host, so the mount
    # is a harmless no-op when the operator has not set the variable
    default_source = mount.split(":-", 1)[1].split("}", 1)[0]
    assert default_source == "/dev/null"

    # the .dockerignore side of the fix (already covered by
    # test_dockerignore.py) must still hold: the font stays excluded
    root = os.path.dirname(_SERVER)
    with open(os.path.join(root, ".dockerignore"), encoding="utf-8") as f:
        di = f.read()
    assert "server/webroot/fonts/SharpSans-Bold.woff2" in di
