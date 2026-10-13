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


def test_kubernetes_token_rotation_reuses_protected_installation_files():
    install = _document("install/kubernetes.md")
    rotations = _document("admin-guide/rotations.md")
    token_section = rotations.split("## Rotate the certificate that devices trust", 1)[0]
    kube = token_section.split("### On Kubernetes", 1)[1]
    for name in ("current", "previous"):
        argument = f"--from-file={name}=/secure/path/management-{name}"
        assert argument in install
        assert kube.count(argument) == 2
        assert f"iris-tier-auth/{name}" not in kube
    assert "umask 077" in kube
    assert "cp /secure/path/management-current /secure/path/management-previous" in kube
    assert "**Inventory**" in kube
    assert "#3-create-the-namespace-keys-and-certificates" in kube


def test_browser_import_distinguishes_saved_override_from_each_live_listener():
    page = " ".join(_document("install/certificates-and-tokens.md").split())
    help_text = " ".join((ROOT / "server/webroot/help-server.html").read_text().split())
    assert "saved but reload was not confirmed" in page
    assert "restart the others too" in page
    assert "new trusted connection to each Console" in page
    assert "reload reaches only the Console that handled the request" in page
    assert "saved but reload was not confirmed" in help_text
    assert "Restart other Console instances too" in help_text
    assert "new trusted connection to each instance" in help_text


def test_scheduled_management_credential_check_uses_inventory_navigation():
    page = _document("admin-guide/key-maintenance.md")
    help_text = " ".join((ROOT / "server/webroot/help-server.html").read_text().split())
    assert "replacement, open **Inventory**" in page
    assert "load **Devices**" not in page
    assert "scheduled management credential replacement" in help_text
    assert "<strong>Inventory</strong> and verify every Console" in help_text
    assert "<strong>Retire previous credential</strong>" in help_text


def test_security_distinguishes_separate_holders_from_automatic_local_keys():
    page = " ".join(_document("architecture/security-model.md").split())
    runbook = " ".join((ROOT / "docs/dev/ai-assisted-deployment.md").read_text().split())
    setup = (ROOT / "tools/iris_installer/local_setup.py").read_text()
    assert 'for name in ("root-a", "root-b"):' in setup
    assert 'automatic_keys.create_root(name, folder / name)' in setup
    assert "each person keeps one private root key in a separate location" in page
    assert "Lose one private root key and the surviving root" in page
    assert "both private keys and their random passphrase files in a protected folder on the deployment host" in page
    assert "A host compromise can expose both keys" in page
    assert "Only the public root keys enter deployment containers and volumes" in page
    assert "both locally stored keys and their passphrases" in runbook
    assert "Two people hold the two private halves, in two places, and neither half reaches the server" not in page


def test_guest_shell_distinguishes_publication_marker_from_file_copy_and_readiness():
    page = " ".join(_document("install/guest-shell.md").split())
    publisher = (ROOT / "device/guestshell-publish.sh").read_text()
    assert 'marker="IRIS-INPUTS-PUBLISHED:$CAP:${expected[7]#*:}"' in publisher
    assert "Guest Shell inputs published; bundle acceptance and runtime startup are separate checks" in publisher
    assert "installer's `inputs published` confirmation" in page
    assert "A file-copy confirmation alone does not prove this" in page
    assert "later bundle decision" in page and "latest heartbeat separately" in page


def test_peer_reporting_guidance_names_streaming_onboarding_prerequisite():
    page = " ".join(_document("user-guide/console.md").split())
    help_text = " ".join((ROOT / "server/webroot/help-device.html").read_text().split())
    contributor = " ".join((ROOT / "docs/dev/telemetry-internals.md").read_text().split())
    ui = (ROOT / "server/console-ui/src/inventory-actions.jsx").read_text()
    for setting, label in (("telemetry", "Telemetry reports"), ("telemetry_stream", "Live telemetry")):
        assert re.search(r"checkbox\('" + setting + r"', '[^']+', '" + label + r"'\)", ui)
        assert f"**{label}**" in page
        assert f"<strong>{label}</strong>" in help_text
    assert "Device-to-device arrows and faster reporting need" in page
    assert "enabled when you onboard the device" in page
    assert "monitoring.md#turn-on-and-tune-live-transfer-samples" in page
    assert "enabled when you onboard the device" in help_text
    assert "interval does not turn streaming on" in help_text
    assert "`telemetry` and `telemetry_stream` settings to be enabled" in contributor
    for name in ("user-guide/monitoring.md", "reference/device-configuration.md"):
        assert "Console's **Live telemetry** checkbox" in _document(name)
        assert "Telemetry streaming" not in _document(name)
