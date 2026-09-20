# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0
"""Keep working notes and release evidence out of the published repo root."""

from pathlib import Path
import subprocess


ROOT = Path(__file__).resolve().parents[2]
ROOT_FILES = {
    ".dockerignore", ".gitignore", "CHANGELOG.md", "CODE_OF_CONDUCT.md",
    "CONTRIBUTING.md", "DEVELOPMENT.md", "LICENSE", "MAINTAINERS.md", "NOTICE",
    "README.md", "SECURITY.md", "TESTING.md", "VERSION", "requirements-dev.txt",
    "requirements-docs.txt", "zensical.toml",
}


def test_tracked_root_contains_only_reviewed_project_files():
    tracked = subprocess.check_output(
        ["git", "ls-files", "-z"], cwd=ROOT, text=True,
    ).split("\0")
    root_files = {name for name in tracked if name and "/" not in name}
    assert root_files == ROOT_FILES, (
        "Review root additions; working notes and evidence belong in ignored "
        f"agentinfo/: unexpected={root_files - ROOT_FILES}, "
        f"missing={ROOT_FILES - root_files}"
    )
