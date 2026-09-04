# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Locally generated, host-specific or licensed files must be gitignored.

Two of these only escaped tracking because nobody had run ``git add`` on them:
``server/docker-compose.override.yml`` carries box-local ports, IPs and mounts
(issue #27), and a default ``tools/build-xr-package.sh`` run drops a multi-MB
``iris-xr.rpm`` into ``device/xr/out/`` (issue #79) -- while the IOx build's
``device/iox/out/`` was already ignored.

The rules are evaluated in a throwaway repository holding only this
repository's ``.gitignore``, with the user's global and system git config
neutralised, so a rule that actually lives in ``.git/info/exclude`` or in a
personal ``core.excludesFile`` cannot make the assertion pass.
"""

import os
import shutil
import subprocess

import pytest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))

# (path, must_be_ignored)
CASES = [
    ("server/docker-compose.override.yml", True),
    ("device/xr/out/iris-xr.rpm", True),
    ("device/xr/out/iris-xr.rpm.manifest", True),
    ("device/iox/out/iris.tar", True),
    ("device/iox/out/iris-arm64.tar.manifest", True),
    ("artifacts/iris-device-test.oci.tar", True),
    ("artifacts/iris-device-test.oci.tar.manifest", True),
    # Negative controls: an over-broad rule (`docker-compose.*`, `device/xr/`)
    # that swallowed tracked source would still satisfy the checks above.
    ("server/docker-compose.yml", False),
    ("device/container/entrypoint.sh", False),
    ("device/xr/tests/test_build_xr_package.bats", False),
]


@pytest.fixture(scope="module")
def sandbox(tmp_path_factory):
    if shutil.which("git") is None:
        pytest.skip("git not available")
    work = tmp_path_factory.mktemp("gitignore")
    shutil.copyfile(os.path.join(ROOT, ".gitignore"), str(work / ".gitignore"))
    env = dict(os.environ)
    env.update({
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_SYSTEM": os.devnull,
        "HOME": str(work),
    })
    subprocess.run(["git", "init", "-q", str(work)], check=True, env=env)
    for rel, _ in CASES:
        target = work / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("x\n")
    return work, env


@pytest.mark.parametrize("rel,ignored", CASES)
def test_gitignore_rules(sandbox, rel, ignored):
    work, env = sandbox
    proc = subprocess.run(
        ["git", "-C", str(work), "check-ignore", "-q", "--", rel],
        env=env,
    )
    assert proc.returncode in (0, 1), "git check-ignore failed on %s" % rel
    assert (proc.returncode == 0) is ignored, (
        "%s is %signored by .gitignore" % (rel, "" if proc.returncode == 0 else "NOT ")
    )
