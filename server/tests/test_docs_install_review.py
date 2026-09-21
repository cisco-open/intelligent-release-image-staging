# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Exercise the installation guide's public-certificate export contract."""

from pathlib import Path
import re
import shutil
import subprocess

import pytest


ROOT = Path(__file__).resolve().parents[2]
INSTALL = ROOT / "docs/zensical/install"


def test_signing_root_commands_keep_private_keys_on_separate_holders(tmp_path):
    if not shutil.which("ssh-keygen"):
        pytest.skip("ssh-keygen required")
    page = (INSTALL / "signing-roots.md").read_text()
    blocks = re.findall(r"```bash\n(.*?)```", page, re.DOTALL)
    holders = [tmp_path / "holder-a", tmp_path / "holder-b"]
    build = tmp_path / "build"
    incoming = build / "iris-root-import"
    incoming.mkdir(parents=True)
    for holder, name, block in zip(holders, ("root-a", "root-b"), blocks[:2]):
        holder.mkdir()
        # Supply a passphrase for the test's otherwise-interactive key creation.
        command = block.replace("~/", str(holder) + "/").replace(
            "ssh-keygen -t", "ssh-keygen -q -N test-fixture-passphrase -t")
        subprocess.run(["bash", "-euc", command], check=True, capture_output=True)
        custody = holder / "iris-custody"
        assert {p.name for p in custody.iterdir()} == {name, name + ".pub"}
        shutil.copyfile(custody / (name + ".pub"), incoming / (name + ".pub"))
    subprocess.run(["bash", "-euc", blocks[2].replace("~/", str(build) + "/")],
                   check=True, capture_output=True)
    roots = build / "iris-roots"
    assert {p.name for p in roots.iterdir()} == {"root-a.pub", "root-b.pub"}
    for name in ("root-a.pub", "root-b.pub"):
        assert (roots / name).read_bytes() == (incoming / name).read_bytes()
    assert all(p.suffix == ".pub" for p in build.rglob("*") if p.is_file())


def test_documented_export_does_not_distribute_private_key(tmp_path):
    if not shutil.which("openssl"):
        pytest.skip("openssl required")
    key, cert = tmp_path / "key.pem", tmp_path / "cert.pem"
    subprocess.run([
        "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
        "-days", "1", "-subj", "/CN=docs-test", "-keyout", str(key),
        "-out", str(cert),
    ], check=True, capture_output=True)
    combined = tmp_path / "combined.pem"
    combined.write_bytes(cert.read_bytes() + key.read_bytes())
    page = (INSTALL / "certificates-and-tokens.md").read_text()
    command = re.search(
        r"openssl x509 -in /run/iris/tls/console-fallback\.pem -outform PEM",
        page,
    )
    assert command, "Export the certificate inside the container, not its key"
    args = command.group().split()
    args[args.index("-in") + 1] = str(combined)
    exported = subprocess.run(args, check=True, capture_output=True).stdout
    assert exported == cert.read_bytes()
    assert b"PRIVATE KEY" not in exported
    assert "cat /run/iris/tls/console-fallback.pem" not in page


def test_first_sign_in_establishes_trust_before_password_entry():
    page = (INSTALL / "first-sign-in.md").read_text()
    assert "continue past the warning" not in page
    assert "before signing in" in page
    assert "certificates-and-tokens.md#default-browser-identity" in page


def test_split_install_prepares_environment_before_build():
    page = (INSTALL / "separate-docker-hosts.md").read_text()
    for service in ("server", "console"):
        assert page.index(f"cp server/{service}.env.example") < page.index(
            f"iris_{service} build --pull")
        assert page.index(f"iris_{service} build --pull") < page.index(
            f"iris_{service} up -d")
    assert "contents" in page
    assert "/etc/iris/docker-hosts/tier-auth/current.json" in page
    assert page.index(". server/server.env") < page.index("iris_server build --pull")


def test_cluster_certificates_are_created_before_secret_imports():
    page = (INSTALL / "kubernetes.md").read_text()
    assert page.index("tools/prepare-docker-hosts.py") < page.index(
        "create secret tls iris-management-tls")
    for name in ("iris-server-api", "iris-server-api.iris", "iris-server-api.iris.svc"):
        assert f"--management-host {name}" in page
    assert "openssl x509 -in /run/iris/tls/cert.pem -outform PEM" in page
