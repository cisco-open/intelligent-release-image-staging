# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Execute the documented readiness decision and guard recovery commands."""
import json
import importlib.util
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


def test_replacement_requires_backup_undeploy_removal_and_new_installation():
    source = _document("admin-guide/upgrade.md")
    assert re.findall(r"^## (\d+)\.", source, re.M) == ["1", "2", "3"]
    assert '## 1. Back up and undeploy' in source
    assert '## 2. Remove the old deployment' in source
    assert '## 3. Install and onboard' in source
    assert 'irisctl upgrade' not in source and 'git checkout' not in source
    assert 'new state directory and' in source
    assert 'not automatically adopted' in source


def test_uninstall_explains_retained_kubernetes_data_and_controller_credentials():
    page = " ".join(_document("admin-guide/uninstall.md").split())
    assert "`--purge-data`" in page
    assert "A `Retain` policy keeps the volume and its data after the claim is removed" in page
    assert "storage administrator" in page
    assert "Private files retained on the controller can still contain credentials" in page


def test_replacement_docs_preserve_historical_link_and_no_adoption_boundary():
    page = ' '.join(_document('admin-guide/upgrade.md').split())
    developer = ' '.join((ROOT / 'docs/dev/installer.md').read_text().split())
    assert '### Managed deployment replacement { #managed-single-host-docker }' in page
    assert 'run it from the original controller' in page.lower()
    assert 'it is not a cross-deployment migration procedure' in page
    assert 'does not adopt old volumes' in developer
    assert 'Historical operation guards' in developer
    assert 'There is no public in-place application upgrade command' in developer


def test_contributor_rollout_notes_match_catalog_and_report_identifiers():
    page = ' '.join((ROOT / 'docs/dev/upgrade-notes.md').read_text().split())
    assert "`plans` map is keyed by image ID" in page
    assert 'stores the `plan_id` locally and reports the `transfer_id`' in page
    assert 'A report carrying a different transfer ID must not advance the plan' in page


def test_backup_signer_setup_names_the_producer_and_independent_trust_step():
    page = " ".join(_document("admin-guide/backups.md").split())
    upgrade = _document("admin-guide/upgrade.md")
    help_text = (ROOT / "server/webroot/help-server.html").read_text()
    producer = (ROOT / "tools/iris_installer/backup.py").read_text()
    consumer = (ROOT / "tools/iris_installer/managed_worker.py").read_text()
    assert "directory = journal.directory / 'backup-custody'" in producer
    assert "directory / 'signer.pub'" in producer
    assert "source == state or state in source.parents" in consumer
    assert "Independent public signer does not match this deployment backup signer" in consumer
    assert "wait for `captured`" in page
    assert "<installation-state-directory>/backup-custody/signer.pub" in page
    assert "fingerprint with `ssh-keygen -lf <public-file>`" in page
    assert "outside the installation state" in page
    assert "trust-signer" in page and "--signer /protected/path/backup-signer.pub" in page
    assert "signer supplied only with the selected archive is not independent trust" in page
    assert "backups.md#trust-the-backup-signer" in upgrade
    assert "backups/#trust-the-backup-signer" in help_text
    assert "backup-custody/signer.pub" in help_text


def test_iox_assembly_is_unsigned_and_native_signing_is_separate():
    builder = (ROOT / "device/iox/build.sh").read_text()
    contributor = (ROOT / "docs/dev/device-packages.md").read_text()
    assert '"$IOXCLIENT" package --skip-signing .' in builder
    assert "assembles an unsigned package offline" in contributor
    assert "iox.md#native-package-signing" in contributor
    assert "assembles and signs" not in contributor


def test_release_checklist_uses_the_matching_client_for_each_architecture():
    checklist = " ".join((ROOT / "docs/dev/release-checklist.md").read_text().split())
    assert "matching checksum-pinned aria2c client for each architecture" in checklist
    assert "same pinned aria2c binary" not in checklist


def test_prebuilt_release_docs_separate_independent_input_validation_authentication_and_publication():
    installer = " ".join((ROOT / "docs/dev/installer.md").read_text().split())
    checklist = " ".join((ROOT / "docs/dev/release-checklist.md").read_text().split())
    assert "tools/hosted-prebuilt-stage.py" in installer
    assert "complete candidate/source validator before attestation" in installer
    assert "artifact API binds the run and ZIP digest" in installer
    assert "selected attempt must also match the unsigned stage record" in installer
    assert "keyring from the operating system, rather than the incoming artifact" in installer
    for page in (installer, checklist):
        assert "Source-only tag builds remain available" in page
        assert "prepare-prebuilt.yml" in page
        assert "tools/prebuilt-intake.py" in page
        assert "manifest is uploaded last" in page.lower()
        assert "exact release tag" in page
        assert "authenticate <tag> <candidate-evidence SHA256>" in page
        assert "prepared-host" in page and "ubuntu-dependencies" in page
    assert "Neither source-review authority nor validation roots come from the ZIP" in checklist
    assert "does not qualify or publish it" in checklist
    assert "iris-release-qualification-v2" in checklist
    for retired in ("Prebuilt authentication still needs", "prebuilt upload and authentication require",
                    "Release preparation refuses the new prebuilt assets"):
        assert retired not in installer + checklist


def test_prebuilt_intake_docs_require_separate_upload_authority_and_same_intent_reconciliation():
    installer = " ".join((ROOT / "docs/dev/installer.md").read_text().split())
    assert "existing empty draft" in installer
    assert "separate repository write authority" in installer
    assert "--confirmation 'upload prebuilt intake <reported-plan-sha256>'" in installer
    assert "Resume uses the same plan and command" in installer
    assert "stops without repeating the POST" in installer
    assert "Preserve the plan and upload state" in installer
    assert "independent keyring/pip hashes" in installer
    assert "helper never creates a draft, changes a tag or publishes a release" in installer
    assert "prepare prebuilt intake <tag> <manifest SHA256>" in installer
    assert "Set `GH_TOKEN` in the environment for both local commands" in installer
    assert "draft-read access" in installer and "contents-write access" in installer
    assert 'export GH_TOKEN="$(/usr/bin/gh auth token --hostname github.com)"' in installer
    assert "modeled local tests do not prove that permission behavior" in installer


def test_manual_server_build_requires_emulation_before_iox_registration():
    start = (ROOT / "tools/start-compose-server.sh").read_text()
    stage = (ROOT / "tools/stage-iox-package.sh").read_text()
    operator = " ".join(_document("reference/manual-installation/build-tools.md").split())
    contributor = " ".join((ROOT / "docs/dev/device-packages.md").read_text().split())
    assert "ARM64 emulation is not enabled on the Docker build host" in start
    assert '"tonistiigi/binfmt@$BINFMT_IMAGE_DIGEST" --install arm64' in stage
    assert "before building the server" in operator
    assert "arm64 IOx staging helper can register" in operator
    assert "direct image builds need the handler ready before building" in contributor


def test_kubernetes_token_rotation_reuses_protected_installation_files():
    install = _document("reference/manual-installation/kubernetes.md")
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


def test_monitoring_explains_the_actual_sampling_limits():
    path = ROOT / "device/agent/telemetry_report.py"
    spec = importlib.util.spec_from_file_location("docs_telemetry_report", path)
    telemetry = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(telemetry)
    page = " ".join(_document("user-guide/monitoring.md").split())
    assert f"{telemetry.RTT_CONSTRAINED_MS} ms" in page
    assert telemetry.SLOW_BPS == 1024 * 1024
    assert "below 1 MiB/s" in page
    assert telemetry.FAIL_STREAK_BAD == 3
    assert "Three consecutive catalog failures stop sampling" in page
    assert telemetry.STREAM_TIER_TICKS == {"good": 1, "constrained": 4}
    assert "Every 4th tick (~4 min)" in page
    assert "10-second setting applies only while sampling is `good`" in page
    assert "idle seeder suppresses repeated idle reports" in page
    # A quick catalog round trip does not override the image's slow average.
    link = {"link": {"rtt_ms": [22, 26], "fail_streak": 0}}
    assert telemetry.classify(link, telemetry.SLOW_BPS - 1) == "constrained"
    assert telemetry.classify(link, telemetry.SLOW_BPS) == "good"


def test_interrupted_backup_readers_fail_without_adopting_partial_extraction():
    page = " ".join(_document("admin-guide/backups.md").split())
    help_text = " ".join((ROOT / "server/webroot/help-server.html").read_text().split())
    assert "worker restarts during verification or isolated extraction" in page
    assert "marked failed" in page and "Start a new request" in page
    for text in (page, help_text):
        assert "Partial extraction files remain private on the host" in text
        assert "not verified recovery data" in text
    assert "Running work and interrupted deployment changes block new maintenance" in help_text
