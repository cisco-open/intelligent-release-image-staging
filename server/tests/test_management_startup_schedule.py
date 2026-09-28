# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Admission at the management construction/shutdown boundary."""
import contextlib
import signal
import threading
from types import SimpleNamespace

import catalog
import gui_creds
import gui_fleet
import gui_images
import management_api
import pytest
import schedule_runner
import schedules


@pytest.mark.parametrize("startup", (
    "pending-term", "admission-term", "normal", "callback-failure"))
def test_management_schedule_admission_and_startup_cleanup(
        tmp_path, monkeypatch, startup):
    now = 1788955200
    store = schedules.ScheduleStore(str(tmp_path))
    snapshot = {"revision": 1, "now": now, "device_ids": ["edge-1"]}
    store.create("due", {
        "kind": "assign",
        "target": {"device_ids": ["edge-1"], "bind": "late"},
        "payload": {"image_ids": ["image-1"]},
        "when": {"kind": "once", "at": now, "window_seconds": 300},
    }, actor="console:alice", now=now - 1, preview=snapshot)
    admitted = []
    lifecycle = []
    writers = []
    previous_term = signal.getsignal(signal.SIGTERM)

    class Executor:
        def validate(self, *_args, **_kwargs):
            return None

        def dispatch(self, _schedule, _occurrence, device_id, _prior):
            admitted.append(device_id)
            return {"status": "ok", "reason": "assigned"}

    real_runner = schedule_runner.ScheduleRunner

    def construct_runner(*args, **kwargs):
        kwargs["now_fn"] = lambda: now
        runner = real_runner(*args, **kwargs)
        original_pass = runner.run_once

        def one_pass():
            try:
                return original_pass()
            finally:
                runner.stop()

        runner.run_once = one_pass
        return runner

    class ControlledThread:
        """Run one real scheduler pass deterministically; other loops stay inert."""
        def __init__(self, target, args, **_kwargs):
            self.target, self.args = target, args
            self.ident = None
            self.start_attempted = False
            self.writer_failed = False
            self.writer_finished = threading.Event()
            writers.append(self)

        def start(self):
            self.start_attempted = True
            if startup == "callback-failure" and \
                    self.target is management_api.instruction_keys.status_loop:
                # A failed launch must remain nonclean without delaying this
                # deterministic fixture for the production drain deadline.
                self.writer_failed = True
                self.writer_finished.set()
                raise RuntimeError("background start failed")
            self.ident = 1
            try:
                if isinstance(getattr(self.target, "__self__", None), real_runner):
                    if startup == "admission-term":
                        signal.raise_signal(signal.SIGTERM)
                    self.target(*self.args)
            finally:
                self.writer_finished.set()

        def join(self, **_kwargs):
            pass

        def is_alive(self):
            return False

    class Control:
        def __init__(self, *_args):
            # This is the real installed signal handler, before admission.
            if startup == "pending-term":
                signal.raise_signal(signal.SIGTERM)

        def start(self):
            lifecycle.append("control-start")

        def close(self):
            lifecycle.append("control-close")

    cert = tmp_path / "public.crt"
    cert.write_text("test public certificate")
    monkeypatch.setenv("IRIS_STATE", str(tmp_path))
    monkeypatch.setenv("IRIS_MANAGEMENT_API_CERT", str(cert))
    monkeypatch.setenv("IRIS_MANAGEMENT_API_TOKEN_FILE", str(tmp_path / "unused"))
    monkeypatch.setattr(management_api.tier_auth, "load_pair", lambda *_: None)
    monkeypatch.setattr(management_api, "read_instance_id", lambda *_: None)
    monkeypatch.setattr(management_api, "_log_peer_policy_startup", lambda *_: None)
    monkeypatch.setattr(management_api.gui_app, "GuiApp", lambda *a, **k: object())
    monkeypatch.setattr(gui_fleet, "FleetStore", lambda *_: object())
    monkeypatch.setattr(gui_creds, "CredentialStore", lambda *a, **k:
                        SimpleNamespace(audit_export_secrets=lambda: {}))
    monkeypatch.setattr(catalog, "CatalogStore", lambda *a, **k:
                        SimpleNamespace(forget_device=lambda *_: None))
    monkeypatch.setattr(catalog, "Catalog", lambda *a, **k:
                        SimpleNamespace(materialize_bootstrap_instruction=lambda *_: None))
    refresh_calls = []

    def refresh(*args, **kwargs):
        refresh_calls.append((args, kwargs))
        return {"outcome": "ok"}

    def image_service(*args, **kwargs):
        kwargs["verification_fn"]({"id": "new-image"})
        return SimpleNamespace(shutdown=lambda timeout:
                               lifecycle.append("images-drain") or True)

    monkeypatch.setattr(management_api.bulkhash_refresh, "run_refresh", refresh)
    monkeypatch.setattr(gui_images, "ImageService", image_service)
    monkeypatch.setattr(management_api.deployment_records, "DeploymentRecordStore",
                        lambda *_: SimpleNamespace(path=str(tmp_path / "records"),
                        recover_interrupted=lambda: lifecycle.append("recover")))
    monkeypatch.setattr(management_api.iox_verification,
                        "_load_or_create_controller_id", lambda *_: "controller")
    monkeypatch.setattr(management_api.iox_verification, "IoxController",
                        lambda *a, **k: SimpleNamespace(
                            close=lambda: lifecycle.append("controller-close")))
    monkeypatch.setattr(management_api.gui_onboard, "OnboardService",
                        lambda *a, **k: SimpleNamespace(
                            shutdown=lambda: lifecycle.append("onboard-shutdown")))
    server = SimpleNamespace(
        schedule_store=store, schedule_target_resolver=lambda _: snapshot,
        schedule_executor=Executor(),
        schedule_role_guard=lambda *_: contextlib.nullcontext(), tls_active=True,
        serve_forever=lambda: lifecycle.append("serve"),
        stop_request_admission=lambda: lifecycle.append("requests-fence"),
        drain_requests=lambda timeout: lifecycle.append("requests-drain") or True,
        server_close=lambda: lifecycle.append("server-close"))
    monkeypatch.setattr(management_api, "make_server", lambda *a, **k: server)
    monkeypatch.setattr(schedule_runner, "ScheduleRunner", construct_runner)
    monkeypatch.setattr(management_api.iox_verification, "IoxControlServer", Control)
    monkeypatch.setattr(management_api, "_ManagedWriterThread", ControlledThread)
    monkeypatch.setattr(management_api, "_manual_ca_writers", lambda: [])
    # This main() fixture must not permanently close the real module-global
    # export admission used by independent API tests later in the same suite.
    monkeypatch.setattr(management_api.audit_export, "drain_exports",
                        lambda timeout: lifecycle.append("exports-drain") or True)
    monkeypatch.setattr(management_api.instruction_stamper, "InstructionStamper",
                        lambda *a, **k: object())

    if startup == "callback-failure":
        with pytest.raises(RuntimeError, match="^Management writers did not finish cleanly"):
            management_api.main()
    else:
        management_api.main()

    assert len(refresh_calls) == 1
    assert signal.getsignal(signal.SIGTERM) is previous_term
    assert all(writer.args[0].is_set() for writer in writers)
    assert refresh_calls[0][1]["wait"] is True
    assert refresh_calls[0][1]["use_offline_cache"] is True
    terminated = startup in ("pending-term", "admission-term")
    assert admitted == ([] if terminated else ["edge-1"])
    assert len(schedules.OccurrenceStore(str(tmp_path)).list()) == \
        (0 if terminated else 1)
    expected_start = ["recover"]
    if startup == "normal":
        expected_start += ["control-start", "serve"]
    assert lifecycle == expected_start + ["requests-fence", "requests-drain",
                         "images-drain", "exports-drain", "control-close",
                         "server-close", "onboard-shutdown", "controller-close"]
