# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Execute the documented readiness decision and guard recovery commands."""
import json
from pathlib import Path
import re
import sys

import pytest

ROOT = Path(__file__).resolve().parents[2]
DOCS = ROOT / "docs/zensical"


def _document(name):
    return (DOCS / name).read_text()


def _poll_exit(tmp_path, monkeypatch, row, now=2000, after=1900):
    source = _document("user-guide/automation.md")
    snippet = re.search(r"<<'PY'\n(.*?)\nPY", source, re.S).group(1)
    (tmp_path / "devices.json").write_text(json.dumps({
        "devices": [row], "now": now}))
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(sys, "argv", ["-", "switch-a", "image-a", str(after)])
    with pytest.raises(SystemExit) as result:
        exec(compile(snippet, "automation.md", "exec"), {})
    return result.value.code


@pytest.fixture
def ready_row():
    return {"device_id": "switch-a", "last_seen": 1999,
            "assigned_image_ids": ["image-a"], "current_image_id": "image-a",
            "stage_state": "ready"}


def test_documented_poll_accepts_fresh_current_ready(tmp_path, monkeypatch, ready_row):
    assert _poll_exit(tmp_path, monkeypatch, ready_row) == 0


@pytest.mark.parametrize("change", [
    {"stage_state": "copy_failed"},
    {"last_seen": 1899},
    {"last_seen": None},
    {"last_seen": 2001},
    {"assigned_image_ids": []},
    {"device_id": "switch-a-other"},
    {"current_image_id": "image-b"},
    {"staged_image_ids": ["image-a"], "errored_image_ids": ["image-a"]},
    {"staged_image_ids": []},
])
def test_documented_poll_rejects_stale_wrong_or_failed_status(
        tmp_path, monkeypatch, ready_row, change):
    ready_row.update(change)
    assert _poll_exit(tmp_path, monkeypatch, ready_row) == 1


def test_documented_poll_rejects_offline_heartbeat(tmp_path, monkeypatch, ready_row):
    ready_row["last_seen"] = 1400
    assert _poll_exit(tmp_path, monkeypatch, ready_row, after=1300) == 1


def test_documented_poll_reads_multi_image_status(tmp_path, monkeypatch, ready_row):
    ready_row.update(current_image_id="image-b", stage_state="staging",
                     staged_image_ids=["image-a"], errored_image_ids=["image-b"])
    assert _poll_exit(tmp_path, monkeypatch, ready_row) == 0


def test_admin_reset_uses_live_runtime_not_empty_one_shot_container():
    source = _document("admin-guide/maintenance.md")
    assert 'exec iris iris-gui-admin "<username>"' in source
    assert "run --rm iris iris-gui-admin" not in source
    assert "server must be running" in source


def test_upload_and_import_both_document_csrf():
    source = _document("user-guide/images.md")
    assert "Both routes need an authenticated session and the `X-CSRF-Token`" in source


def test_documented_wait_is_bounded_and_times_out_unsuccessfully():
    source = _document("user-guide/automation.md")
    assert "deadline=$((SECONDS + 3600))" in source
    assert "while (( SECONDS < deadline ))" in source
    assert 'test "$staged" -eq 1' in source


def test_upgrade_keeps_three_steps_and_passes_reviewed_roots():
    source = _document("admin-guide/upgrade.md")
    assert re.findall(r"^## (\d+)\.", source, re.M) == ["1", "2", "3"]
    assert "IRIS_INSTRUCTION_ROOTS_DIR=/path/to/reviewed/roots" in source
    assert "### Onboard the devices again" in source
