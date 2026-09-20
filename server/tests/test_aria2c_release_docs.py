# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0
"""Keep source publication and operator recovery guidance aligned."""
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def read(path):
    return (ROOT / path).read_text()


def test_troubleshooting_preserves_precompiled_clients_and_checksum_gate():
    text = read("docs/zensical/user-guide/troubleshooting.md")
    assert "A checkout includes both tested clients" in text
    assert "Do not bypass checksum verification or substitute an unverified build" in text
    assert "Never edit `tools/aria2c.sha256` to silence a mismatch" in text


def test_developer_build_guidance_allows_exact_reproduction():
    text = read("docs/dev/device-packages.md")
    assert "A rebuilt binary may differ" in text
    assert "Matching inputs can reproduce the shipped bytes" in text
    assert "will not match `tools/aria2c.sha256`" not in text
    assert "keeps every core busy" not in text
    assert "ARIA2C_BUILD_JOBS" in text
    assert "Source archives supplement the" in text
    assert "Never edit `tools/aria2c.sha256` to silence a mismatch" in text


def test_release_guides_require_source_beside_precompiled_binaries():
    for path in ("docs/dev/release-checklist.md", "DEVELOPMENT.md"):
        text = read(path)
        assert "tools/aria2c-source/README.md" in text
        assert "source archive" in text
        assert "checksum" in text
    checklist = read("docs/dev/release-checklist.md")
    assert "aria2c-2.5.6-p10-source.tar.gz" in checklist
    assert "both binaries" in checklist
    assert "Keep older release tags and assets intact" in checklist


def test_device_package_reuse_preserves_instruction_root_boundary():
    text = read("docs/dev/device-packages.md")
    assert "the two approved instruction roots" in text
    assert "Reuse them only across deployments that trust those same roots" in text
    assert "Within each architecture" in text
    assert "one signed set of packages works\nacross every deployment" not in text
