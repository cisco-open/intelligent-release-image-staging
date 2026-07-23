# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for the container-mode CLI-over-SSH transport (cli_ssh).

The shim must make an SSH-to-self IOS session look EXACTLY like the Guest Shell
`cli` module to iris_agent.build_deps: `execute(cmd) -> str` returns ONLY the
command's output text (no prompt, no echoed command, no login/enable noise), so
the existing text-exact parsers (flash_target, flashcheck) keep working unchanged.
All tests inject a fake transcript runner -- no real SSH."""
import cli_ssh


# A real raw transcript captured from the IE-3400 (100.90.168.99) over SSH with
# `-tt`. The login lands at priv-15 (prompt `3400-1#`), so the `enable` password
# line runs as a bogus exec command and emits a `% Bad IP address ...` noise line
# BEFORE the real command echo -- it must never leak into extracted output.
IE3400_FS_TRANSCRIPT = """\
\r
\r
\r
3400-1#enable\r
3400-1#REDACTED-PW\r
% Bad IP address or host name% Unknown command or computer name, or unable to find computer address\r
3400-1#terminal length 0\r
3400-1#show file systems\r
File Systems:\r
\r
       Size(b)       Free(b)      Type  Flags  Prefixes\r
             -             -    opaque     rw   system:\r
     518885376     464301056      disk     rw   crashinfo:\r
*   1697755136    1049231360      disk     rw   flash: bootflash:\r
   31232462848   30613917696      disk     rw   sdflash:\r
\r
3400-1#exit\r
"""


def test_extract_output_returns_only_command_output():
    out = cli_ssh.extract_output(IE3400_FS_TRANSCRIPT, "show file systems")
    lines = out.splitlines()
    # the command body is present...
    assert lines[0] == "File Systems:"
    assert "   31232462848   30613917696      disk     rw   sdflash:" in lines
    # ...and none of the prompt/echo/enable noise leaked in
    assert "3400-1#" not in out
    assert "enable" not in out
    assert "Bad IP address" not in out
    assert "terminal length 0" not in out


def test_extract_output_feeds_parse_file_systems_unchanged():
    import flash_target
    out = cli_ssh.extract_output(IE3400_FS_TRANSCRIPT, "show file systems")
    fss = flash_target.parse_file_systems(out)
    prefixes = {p for f in fss for p in f["prefixes"]}
    assert "sdflash:" in prefixes
    sd = next(f for f in fss if "sdflash:" in f["prefixes"])
    assert sd["free"] == 30613917696
    assert sd["type"] == "disk"


def test_extract_output_handles_piped_command_with_special_chars():
    transcript = (
        "3400-1#terminal length 0\r\n"
        "3400-1#show version | include Cisco IOS XE Software\r\n"
        "Cisco IOS XE Software, Version 17.15.04\r\n"
        "3400-1#exit\r\n"
    )
    out = cli_ssh.extract_output(
        transcript, "show version | include Cisco IOS XE Software")
    assert out == "Cisco IOS XE Software, Version 17.15.04"


def test_extract_output_empty_output_command_returns_empty_string():
    # A command that produces no output (echo immediately followed by prompt).
    transcript = (
        "3400-1#delete /force flash:foo\r\n"
        "3400-1#exit\r\n"
    )
    assert cli_ssh.extract_output(transcript, "delete /force flash:foo") == ""


def test_extract_output_raises_when_command_never_ran():
    # No echo line for the command -> the command never reached the device.
    transcript = "3400-1#enable\r\n3400-1#exit\r\n"
    try:
        cli_ssh.extract_output(transcript, "show file systems")
    except cli_ssh.CliTransportError:
        return
    assert False, "expected CliTransportError when command echo is absent"


def test_sshcli_execute_uses_runner_and_extracts():
    captured = {}

    def fake_runner(script):
        captured["script"] = script
        return IE3400_FS_TRANSCRIPT

    cli = cli_ssh.SSHCli(host="100.92.100.253", user="dnac",
                         password="pw", enable="en", runner=fake_runner)
    out = cli.execute("show file systems")
    assert out.splitlines()[0] == "File Systems:"
    # the script the runner was handed drives an enable + terminal length 0 + cmd
    assert "show file systems" in captured["script"]
    assert "terminal length 0" in captured["script"]
    assert "enable" in captured["script"]


def test_sshcli_configure_wraps_lines_in_config_mode():
    captured = {}

    def fake_runner(script):
        captured["script"] = script
        return ("3400-1#configure terminal\r\n"
                "3400-1(config)#event manager applet X\r\n"
                "3400-1(config)#end\r\n3400-1#exit\r\n")

    cli = cli_ssh.SSHCli(host="h", user="u", password="pw", runner=fake_runner)
    cli.configure(["event manager applet X", "event none maxrun 60"])
    s = captured["script"]
    assert "configure terminal" in s
    assert "event manager applet X" in s
    assert "event none maxrun 60" in s
    assert "\nend\n" in s            # config block is closed


def test_sshcli_execute_raises_on_runner_failure():
    def boom(script):
        raise OSError("ssh: connect to host port 22: Connection refused")

    cli = cli_ssh.SSHCli(host="h", user="u", password="pw", runner=boom)
    try:
        cli.execute("show version")
    except cli_ssh.CliTransportError:
        return
    assert False, "expected CliTransportError when the runner raises"


# ---- runtime-mode seam: select the transport without regressing C9300 ----

def test_select_cli_defaults_to_guestshell():
    calls = {}

    def fake_guestshell_import():
        calls["guestshell"] = True
        return ("GS_EXEC", "GS_CONF")

    execute, configure = cli_ssh.select_cli(
        {}, env={}, guestshell_factory=fake_guestshell_import)
    assert calls.get("guestshell") is True
    assert execute == "GS_EXEC" and configure == "GS_CONF"


def test_select_cli_container_mode_builds_ssh_transport():
    cfg = {
        "device_ssh_host": "100.92.100.253",
        "device_ssh_user": "dnac",
        "device_ssh_pass": "REDACTED-PW",
    }

    def explode():
        raise AssertionError("must NOT import guestshell cli in container mode")

    execute, configure = cli_ssh.select_cli(
        cfg, env={"IRIS_RUNTIME_MODE": "container"},
        guestshell_factory=explode)
    # bound to a live SSHCli instance's methods
    assert execute.__self__.__class__ is cli_ssh.SSHCli
    assert configure.__self__ is execute.__self__
    assert execute.__self__.host == "100.92.100.253"


def test_select_cli_container_mode_via_conf_key():
    cfg = {
        "runtime_mode": "container",
        "device_ssh_host": "10.0.0.1",
        "device_ssh_user": "u",
        "device_ssh_pass": "p",
    }
    execute, _ = cli_ssh.select_cli(cfg, env={},
                                    guestshell_factory=lambda: (_ for _ in ()).throw(
                                        AssertionError("should not import guestshell")))
    assert execute.__self__.host == "10.0.0.1"


# ---- emit() must be best-effort: a transport failure must never propagate ----

def test_emit_impl_swallows_transport_failure():
    import iris_agent

    def boom(_cmd):
        raise cli_ssh.CliTransportError("ssh down")

    # Must NOT raise -- losing a syslog line is acceptable; crashing the tick
    # (and masking the real error being logged) is not.
    iris_agent._emit_impl(boom, "TOKEN-REFRESH-FAIL", "catalog unreachable")


def test_emit_impl_builds_sanitized_send_log_command():
    import iris_agent
    seen = {}

    def capture(cmd):
        seen["cmd"] = cmd

    # double-quotes -> single, non-ascii -> replaced (the Guest Shell cli logger
    # crashes on non-ascii); command shape preserved.
    iris_agent._emit_impl(capture, "DONE", 'staged "img" — ok')
    assert seen["cmd"].startswith(
        'send log facility IRIS severity 6 mnemonic DONE "')
    assert '"img"' not in seen["cmd"]      # quotes were downgraded
    assert "'img'" in seen["cmd"]
    assert "—" not in seen["cmd"]     # em-dash replaced


# ---- scp push (container -> device): how the IOx app gets the staged image onto
# the IOS-visible sdflash: (IOx can't bind-mount sdflash:; inbound to the container
# is blocked; container->device SSH is the proven direction). ----

def test_sshcli_put_scps_local_file_to_device():
    seen = {}

    def fake_scp(local, target):
        seen["local"] = local
        seen["target"] = target

    cli = cli_ssh.SSHCli(host="100.92.100.253", user="dnac",
                         password="pw", scp_runner=fake_scp)
    cli.put("/data/iris/x.bin", "sdflash:guest-share/iris/x.bin")
    assert seen["local"] == "/data/iris/x.bin"
    assert seen["target"] == "dnac@100.92.100.253:sdflash:guest-share/iris/x.bin"


def test_sshcli_put_raises_on_scp_failure():
    def boom(local, target):
        raise OSError("scp: connect failed")

    cli = cli_ssh.SSHCli(host="h", user="u", password="p", scp_runner=boom)
    try:
        cli.put("/a/b.bin", "sdflash:b.bin")
    except cli_ssh.CliTransportError:
        return
    assert False, "expected CliTransportError when scp fails"


def test_sshcli_uses_shared_control_connection_for_cli_and_scp():
    cli = cli_ssh.SSHCli(host="h", user="u", password="p",
                          control_path="/data/iris/ios-%r@%h:%p")
    opts = cli._control_options()
    assert "ControlMaster=auto" in opts
    assert "ControlPersist=120" in opts
    assert "ControlPath=/data/iris/ios-%r@%h:%p" in opts
