# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0
"""ARM deployment instructions stay parseable and cover every artifact destination.

These checks never build packages, start containers, or contact a cluster.
"""

import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DOCS = ROOT / "docs" / "zensical"
GUIDE = (DOCS / "aiagent.md").read_text()
ANCHOR = "#build-and-publish-the-arm64-iox-package"
RECIPE = GUIDE.split("## Build and publish the ARM64 IOx package\n", 1)[1].split(
    "\n## ", 1
)[0]


def test_arm_download_keeps_server_binary_and_uses_supported_flag_order():
    assert "tools/get-aria2c.sh --no-install arm64" in RECIPE
    assert not re.search(r"get-aria2c\.sh arm64\s+--no-install", GUIDE)
    assert "cp tools/aria2c-build/out/aarch64/aria2c" not in GUIDE
    assert 'export ARIA2C_BIN_AMD64="$PWD/bin/aria2c"' in RECIPE
    assert 'export ARIA2C_BIN_ARM64="$PWD/deliverables/aria2c-aarch64"' in RECIPE


def test_arm_build_selects_both_platforms_and_private_output():
    assert "export IRIS_DEVICE_PLATFORMS=linux/amd64,linux/arm64" in RECIPE
    assert 'IRIS_ARM_BUILD_DIR="$(mktemp -d)"' in RECIPE
    assert 'export IRIS_DEVICE_IMAGE_OCI="$IRIS_ARM_BUILD_DIR/iris-device.oci.tar"' in RECIPE
    assert 'tools/stage-iox-package.sh --arch arm64 \\\n  --artifacts-dir "$IRIS_ARM_BUILD_DIR"' in RECIPE
    assert "package_readiness" in RECIPE
    assert 'result["state"] == "ok"' in RECIPE


def test_arm_publishing_includes_manifest_and_actual_server_storage():
    docker, k8s = RECIPE.split("### Publish to either Docker layout", 1)[1].split(
        "### Publish to Kubernetes", 1
    )
    for env, compose in ((".env", "docker-compose.yml"),
                         ("server.env", "docker-compose.server.yml")):
        assert f"--env-file server/{env} -f server/{compose} ps -q iris" in docker
    for suffix in ("", ".manifest"):
        assert f'"$IRIS_CONTAINER:/srv/artifacts/.iris-arm64.tar{suffix}.tmp"' in docker
        assert f'"$IRIS_SERVER_POD:/data/artifacts/.iris-arm64.tar{suffix}.tmp"' in k8s
    assert 'test -r .iris-arm64.tar.tmp && test -r .iris-arm64.tar.manifest.tmp' in docker
    assert 'docker exec --user 0 "$IRIS_CONTAINER" chown' not in docker
    assert "kubectl -n iris cp --no-preserve" in k8s
    assert "app.kubernetes.io/name=iris-seed-server" in k8s
    for section in (docker, k8s):
        assert "sha256sum iris-arm64.tar iris-arm64.tar.manifest" in section


def test_all_layouts_link_the_shared_arm_recipe():
    for layout in ("Docker on one host", "Docker on separate hosts", "Kubernetes"):
        section = GUIDE.split(f"### {layout}\n", 1)[1].split("\n### ", 1)[0]
        assert ANCHOR in section, layout
    for page in ("docker-hosts.md", "kubernetes.md"):
        assert f"aiagent.md{ANCHOR}" in (DOCS / page).read_text()


def test_arm_recipe_shell_examples_parse_without_executing():
    blocks = re.findall(r"```bash\n(.*?)\n```", RECIPE, re.S)
    assert len(blocks) >= 5
    for block in blocks:
        parsed = subprocess.run(
            ["bash", "-n"], input=block, text=True, capture_output=True, check=False
        )
        assert parsed.returncode == 0, parsed.stderr


def test_split_docker_initializes_public_roots_before_starting_fresh_server():
    guide = (DOCS / "docker-hosts.md").read_text()
    section = guide.split("## Start the server host\n", 1)[1].split(
        "\n## Start the Console host", 1)[0]
    root_install = 'install -m 0644 /pub/*.pub "$IRIS_CONFIG/instr/roots.d/"'
    assert section.index(root_install) < section.index("iris_server up -d")
    assert 'export IRIS_INSTRUCTION_ROOTS_DIR="$HOME/iris-roots"' in section
    assert "aiagent.md#initialise-instruction-custody" in section
    assert "Do not replace roots on an existing" in section
    for block in re.findall(r"```bash\n(.*?)\n```", section, re.S):
        parsed = subprocess.run(["bash", "-n"], input=block, text=True,
                                capture_output=True, check=False)
        assert parsed.returncode == 0, parsed.stderr


def test_single_docker_guide_keeps_browser_identity_across_restarts():
    section = GUIDE.split("### Docker on one host\n", 1)[1].split(
        "\n### Docker on separate hosts", 1)[0]
    assert "tls/console-fallback.pem.age" in section
    assert "reused on restart" in section
    assert "default changes on server restart" not in GUIDE
