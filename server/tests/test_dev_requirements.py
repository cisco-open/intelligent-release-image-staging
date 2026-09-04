# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""The test suite's own dependencies must be declared, and declared once.

PyYAML was required by fifteen tests and named in no requirements file. Ten of
them (the Kubernetes and compose SECURITY assertions) hid behind
``pytest.importorskip`` and vanished as "skipped" on a machine without it,
while the five siblings in the same area imported ``yaml`` directly and
hard-errored -- so the documented command produced a quietly weaker result
locally than in CI. These tests keep the declaration, the CI installer and the
import style from drifting apart again.
"""
import glob
import os
import re

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
REQ = os.path.join(ROOT, "requirements-dev.txt")
WORKFLOW = os.path.join(ROOT, ".github", "workflows", "tests.yml")


def _requirement_names():
    names = []
    with open(REQ, encoding="utf-8") as stream:
        for line in stream:
            line = line.split("#", 1)[0].strip()
            if line:
                names.append(re.split(r"[<>=!~\[ ]", line, 1)[0].lower())
    return names


def test_requirements_dev_declares_the_test_dependencies():
    assert os.path.exists(REQ), (
        "requirements-dev.txt is missing: a clean machine cannot run the "
        "documented pytest command")
    names = _requirement_names()
    assert "pyyaml" in names, names
    assert "pytest" in names, names


def test_requirements_dev_carries_the_spdx_header():
    with open(REQ, encoding="utf-8") as stream:
        head = stream.read(400)
    assert "SPDX-License-Identifier: Apache-2.0" in head


def test_ci_installs_the_declared_file_rather_than_its_own_list():
    """A hand-maintained `pip install pytest pyyaml` in the workflow is a
    second source of truth that goes stale the first time a dependency is
    added here."""
    with open(WORKFLOW, encoding="utf-8") as stream:
        text = stream.read()
    assert "requirements-dev.txt" in text
    assert not re.search(r"pip install\s+pytest\s+pyyaml", text)


def test_no_test_module_skips_itself_over_a_declared_dependency():
    """importorskip("yaml") turns a missing declared dependency into silence.
    Now that PyYAML is declared, every module imports it directly so the run
    fails loudly instead."""
    offenders = []
    for pattern in ("server/tests/*.py", "device/**/tests/*.py",
                    "lab/tests/*.py"):
        for path in glob.glob(os.path.join(ROOT, pattern), recursive=True):
            if os.path.abspath(path) == os.path.abspath(__file__):
                continue  # this file names the pattern it forbids
            with open(path, encoding="utf-8") as stream:
                body = stream.read()
            if re.search(r"importorskip\(\s*['\"]yaml['\"]", body):
                offenders.append(os.path.relpath(path, ROOT))
    assert offenders == [], offenders
