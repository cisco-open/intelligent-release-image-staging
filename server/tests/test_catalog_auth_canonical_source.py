# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Source/canonical-module guard (Wave 1 integration): catalog authorization
and personalization MUST go through the canonical identity-lane APIs
(``auth`` / ``secrets_store``), never a duplicate ``catalog_auth`` module.

This guard fails closed if the torrent-lane temporary ``catalog_auth`` module
is resurrected, if ``catalog.py`` re-imports it, or if the broad reverse index
(``secrets_store.build_index``) is used for a catalog AUTHORIZATION decision
(spec §6: only the strict index authorizes)."""
import importlib
import os

import pytest

_SERVER_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_CATALOG_SRC = os.path.join(_SERVER_DIR, "catalog.py")


def test_catalog_auth_module_is_gone():
    # The duplicate torrent-lane module must not exist as a file...
    assert not os.path.exists(os.path.join(_SERVER_DIR, "catalog_auth.py"))
    # ...and must not be importable.
    with pytest.raises(ModuleNotFoundError):
        importlib.import_module("catalog_auth")


def test_catalog_source_does_not_import_catalog_auth():
    with open(_CATALOG_SRC) as f:
        lines = f.readlines()
    # No import of the duplicate module, and no attribute access on it. We look
    # for the module used as an identifier (`catalog_auth.` / `import
    # catalog_auth`), not the substring inside `build_catalog_auth_index`.
    for line in lines:
        stripped = line.strip()
        assert not stripped.startswith("import catalog_auth"), \
            "catalog.py must not import the duplicate catalog_auth module"
        assert "catalog_auth." not in line, \
            "catalog.py must not call into the duplicate catalog_auth module"


def test_catalog_uses_canonical_apis():
    with open(_CATALOG_SRC) as f:
        src = f.read()
    # Canonical identity-lane surfaces the catalog now depends on.
    assert "secrets_store.build_catalog_auth_index" in src
    assert "auth.resolve_catalog_auth" in src
    assert "secrets_store.DuplicateCredentialError" in src
    assert "secrets_store.device_announce_value" in src


def test_broad_index_never_authorizes_in_guard():
    """The broad build_index result must only ever be passed to route_post as
    compatibility data — never consulted for an authorization decision. The
    strict catalog auth index is the sole authorization surface (spec §6)."""
    with open(_CATALOG_SRC) as f:
        lines = f.readlines()
    # Locate the _guard method body and assert build_index is not called there.
    in_guard = False
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("def _guard("):
            in_guard = True
            continue
        if in_guard:
            # A dedented def/class ends the guard body.
            if stripped.startswith("def ") and "_guard" not in stripped:
                break
            assert "build_index(" not in line, \
                "_guard must not build the broad reverse index for auth"


def test_canonical_modules_expose_required_surfaces():
    import auth
    import secrets_store
    # Typed principal/context and the catalog resolver live on auth.
    assert hasattr(auth, "Principal")
    assert hasattr(auth, "AuthContext")
    assert callable(auth.resolve_catalog_auth)
    # Strict catalog index + duplicate error + device announce helper on store.
    assert callable(secrets_store.build_catalog_auth_index)
    assert callable(secrets_store.device_announce_value)
    assert issubclass(secrets_store.DuplicateCredentialError, Exception)
