# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Run the shipped React controller against controlled response races."""
import pytest

from test_gui_server import _run_policies_node


@pytest.mark.parametrize("field", ["nets", "restricted"])
def test_edit_while_preview_is_pending_requires_a_new_preview(field):
    _run_policies_node(f"editing {field} during pending preview")


def test_existing_editor_keeps_its_read_revision_and_unedited_overlay():
    _run_policies_node("existing editor holds")


def test_existing_editor_refuses_an_unknown_definition_revision():
    _run_policies_node("capability, degraded policy|mismatched policy/definition")
