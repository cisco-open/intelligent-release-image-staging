# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
"""Early certificate-window checks never adjust a device clock or disable TLS."""
import ssl
import pytest
import iox_verification as module

START = ssl.cert_time_to_seconds('Sep 15 17:04:51 2026 GMT')
END = ssl.cert_time_to_seconds('Sep 16 17:04:51 2026 GMT')

@pytest.mark.parametrize('output', [
    b'*17:03:33.268 UTC Tue Sep 15 2026\r\n',
    b'edge#show clock\r\n.17:04:50 GMT Tue Sep 15 2026\r\nedge#',
])
def test_clock_before_new_certificate_is_actionable(output):
    with pytest.raises(module._ControllerFailure, match='before.*validity'):
        module._check_device_certificate_clock(output, START, END)

def test_expired_certificate_is_distinct():
    with pytest.raises(module._ControllerFailure, match='after.*validity'):
        module._check_device_certificate_clock(
            b'17:04:52 UTC Wed Sep 16 2026\n', START, END)

@pytest.mark.parametrize('clock', ['17:04:51', '17:05:33'])
def test_valid_clock_is_accepted(clock):
    module._check_device_certificate_clock(
        (clock+' UTC Tue Sep 15 2026\n').encode(), START, END)

@pytest.mark.parametrize('output', [b'', b'17:03:33 CET Tue Sep 15 2026\n',
    b'99:99:99 UTC Tue Sep 15 2026\n',
    b'17:03:33 UTC Tue Sep 15 2026\n17:03:34 UTC Tue Sep 15 2026\n'])
def test_unknown_or_ambiguous_clock_is_not_guessed(output):
    module._check_device_certificate_clock(output, START, END)

def test_rejected_clock_precedes_any_trustpoint_mutation(monkeypatch):
    controller = object.__new__(module.IoxController)
    controller._strict_target = True
    controller.config = {'catalog_certificate_path': '/validated-public-cert'}
    calls = []
    monkeypatch.setattr(module, '_open_public_certificate', lambda path: 123)
    monkeypatch.setattr(module.os, 'close', lambda fd: None)
    monkeypatch.setattr(module.ssl._ssl, '_test_decode_cert', lambda path: {
        'notBefore': 'Sep 15 17:04:51 2026 GMT', 'notAfter': 'Sep 16 17:04:51 2026 GMT'})
    controller._render_command = lambda attempt, name: name.encode()
    def command(attempt, name, body, timeout, **kwargs):
        calls.append(name)
        return {'stdout': b'*17:03:33.268 UTC Tue Sep 15 2026\n'}, None
    controller._command = command
    controller._transport_ok = lambda result: True
    with pytest.raises(module._ControllerFailure, match='trustpoint was not changed'):
        controller._ensure_trustpoint(object(), {})
    assert calls == ['clock']
