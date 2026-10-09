# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""A real credential write can commit before its BFF returns transport 503."""

import http.client
import json

import pytest

import gui_creds
import management_api
from test_api_split import policy_tiers


@pytest.mark.parametrize("action", ["save", "delete"])
def test_committed_credential_write_with_lost_reply_is_not_a_refusal(
        tmp_path, monkeypatch, request, action):
    credentials = gui_creds.CredentialStore(str(tmp_path / "secrets.json"))
    factory = management_api.make_server

    def with_credentials(*args, **kwargs):
        return factory(*args, creds=credentials, **kwargs)

    monkeypatch.setattr(management_api, "make_server", with_credentials)
    call, _, _ = request.getfixturevalue("policy_tiers")
    body = dict(id="review-profile", name="Review profile", device_user="operator",
                device_pass="synthetic-password", enable_secret="synthetic-enable")
    if action == "delete":
        credentials.set_profile(body["id"], body)
    endpoint = "/credentials" + ("/review-profile" if action == "delete" else "")
    method = "DELETE" if action == "delete" else "POST"
    requests = []
    putrequest = http.client.HTTPSConnection.putrequest
    getresponse = http.client.HTTPSConnection.getresponse

    def track_path(conn, verb, path, *args, **kwargs):
        conn._review_target = (verb, path)
        return putrequest(conn, verb, path, *args, **kwargs)

    def lose_committed_reply(conn, *args, **kwargs):
        response = getresponse(conn, *args, **kwargs)
        if getattr(conn, "_review_target", None) == (method, "/internal/v1" + endpoint):
            requests.append(conn._review_target)
            # The real state owner has replied 200 only after its durable
            # mutation. Simulate losing that acknowledgement before the BFF
            # can emit its first response byte, not a rejected request.
            assert response.status == 200
            response.close()
            raise http.client.RemoteDisconnected("synthetic lost acknowledgement")
        return response

    monkeypatch.setattr(http.client.HTTPSConnection, "putrequest", track_path)
    monkeypatch.setattr(http.client.HTTPSConnection, "getresponse", lose_committed_reply)
    status, headers, result = call("console", method, endpoint,
                                  body if action == "save" else None, match=False)
    assert status == 503 and result["code"] == "management-api-unavailable"
    assert headers["Retry-After"] == "1"
    assert requests == [(method, "/internal/v1" + endpoint)]
    if action == "save":
        assert credentials.get_secrets(body["id"])["device_pass"] == body["device_pass"]
    else:
        assert credentials.get_secrets(body["id"]) is None
    status, _, public = call("console", "GET", "/credentials", match=False)
    assert status == 200
    assert bool(public["profiles"]) == (action == "save")
    assert "synthetic-password" not in json.dumps([result, public])
    assert "synthetic-enable" not in json.dumps([result, public])
    assert len(requests) == 1, "Neither the BFF nor the follow-up read may replay the write"
