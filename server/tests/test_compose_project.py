# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""The Compose project and container names must be declared, not derived.

Compose falls back to the compose file's parent directory for the project
name. That directory is always ``server``, so a second checkout of this
repository on a host already running IRIS used to resolve to the same project
-- and therefore the same ``server_iris-state`` / ``server_iris-config`` /
``server_iris-images`` volumes -- as the live deployment. ``up`` then adopted
the production container, ``run --rm iris iris-bootstrap`` re-bootstrapped
production state and ``down -v`` deleted it (issue #25).
"""

import os

import yaml

HERE = os.path.dirname(os.path.abspath(__file__))
COMPOSE = os.path.join(HERE, "..", "docker-compose.yml")


def _text():
    with open(COMPOSE) as fh:
        return fh.read()


def _doc():
    return yaml.safe_load(_text())


def test_project_name_is_declared_not_derived():
    doc = _doc()
    assert doc.get("name") == "iris", (
        "server/docker-compose.yml must declare a top-level `name:`; without "
        "one Compose derives the project name from the parent directory "
        "('server'), so a second checkout shares the live deployment's volumes"
    )


def test_container_name_is_overridable_via_iris_container():
    """`docker exec iris ...` must keep working, but a second stack on the
    same host has to be able to rename the container -- container names are
    host-global. IRIS_CONTAINER is the variable tools/ already honours."""
    svc = _doc()["services"]["iris"]
    assert svc["container_name"] == "${IRIS_CONTAINER:-iris}"


def test_volume_migration_snippet_uses_the_declared_project_prefix():
    """The in-file chown migration names real volumes; with `name: iris` the
    prefix is `iris_`, and the old `server_` prefix survives only as the
    documented upgrade note."""
    text = _text()
    for vol in ("iris-state", "iris-config", "iris-images"):
        assert "-v iris_%s:" % vol in text
        assert "-v server_%s:" % vol not in text
    assert "server_" in text, \
        "the upgrade note naming the pre-rename volume prefix must stay"
