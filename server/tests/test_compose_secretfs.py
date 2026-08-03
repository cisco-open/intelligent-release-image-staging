# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""compose wiring for at-rest encryption: a RAM-only tmpfs for plaintext
secrets, the master age key as a read-only Docker secret, and the recipient
+ key-file env. Parsed as YAML — no docker daemon required."""
import os

import pytest

yaml = pytest.importorskip("yaml")

HERE = os.path.dirname(os.path.abspath(__file__))
COMPOSE = os.path.join(HERE, "..", "docker-compose.yml")


def _load():
    with open(COMPOSE) as f:
        return yaml.safe_load(f)


def test_iris_service_mounts_tmpfs_for_run_iris():
    svc = _load()["services"]["iris"]
    mounts = [t for t in svc.get("tmpfs", [])
              if t == "/run/iris" or t.startswith("/run/iris:")]
    assert mounts, \
        "iris service must mount tmpfs at /run/iris for plaintext secrets"
    # non-root runtime: the tmpfs must be owned by uid 10001 and private —
    # a default root:root mount would leave the entrypoint unable to restrict
    # the plaintext dir (it cannot chmod a mountpoint it does not own)
    opts = mounts[0].partition(":")[2].split(",")
    assert "uid=10001" in opts and "gid=10001" in opts and "mode=0700" in opts


def test_age_key_is_a_readonly_docker_secret():
    doc = _load()
    svc = doc["services"]["iris"]
    assert "iris_age_key" in svc.get("secrets", []), \
        "iris service must mount the iris_age_key secret"
    top = doc.get("secrets", {})
    assert "iris_age_key" in top, "top-level secrets must declare iris_age_key"


def test_age_env_present():
    env = _load()["services"]["iris"]["environment"]
    assert "IRIS_AGE_KEY_FILE" in env
    assert "IRIS_AGE_RECIPIENTS" in env
