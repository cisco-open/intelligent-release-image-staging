# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Container-mode CLI transport: SSH-to-self.

On the C9300 the IRIS agent runs INSIDE Guest Shell and reaches IOS through the
in-process `cli` module (`from cli import execute, configure`). The IE-3400 has
no Guest Shell, so the agent runs as a plain aarch64 IOx Docker app and instead
opens an SSH session to the switch's OWN management address (the Vlan666 SVI,
reachable on the app's /30) and runs IOS exactly like `lab/device-run.sh`.

This module makes that SSH session look IDENTICAL to the Guest Shell `cli` module
to `iris_agent.build_deps`:

    execute(cmd: str)        -> str   # ONE exec command, returns ONLY its output
    configure(lines: list)   -> None  # apply config lines in `configure terminal`

`execute` must return the SAME text IOS produces (no prompt, no echoed command,
no enable/login noise) because the downstream parsers (flash_target, flashcheck)
are text-exact. `extract_output` does that scrubbing and is unit-tested against a
real captured IE-3400 transcript.

`select_cli` is the runtime-mode seam: container mode -> this SSH transport;
otherwise the Guest Shell `cli` import (C9300 path, byte-identical). Stdlib only."""
import os
import subprocess


class CliTransportError(RuntimeError):
    """The SSH session failed, or the command never reached the device (its echo
    is absent from the transcript). Mirrors a Guest Shell `cli` call raising:
    the agent's `_show`/`root_present` already treat a raised cli call as a
    transient glitch (return "" / stay True), so one bad tick is harmless."""


def extract_output(transcript, command):
    """Return ONLY `command`'s output from a raw `-tt` SSH transcript.

    The transcript is a sequence of `<prompt>#<echoed-command>` lines, each
    followed by that command's output and terminated by the next `<prompt>#`
    line. We anchor on the exact echo of `command` (so login/enable noise that
    precedes it is excluded) and collect lines until the next prompt. Raises
    CliTransportError if the echo is absent (the command never ran)."""
    text = transcript.replace("\r", "")
    lines = text.split("\n")
    cmd = command.rstrip()
    echo_idx = None
    prompt = None
    for i, line in enumerate(lines):
        before, sep, rest = line.partition("#")
        if sep and rest.rstrip() == cmd:
            echo_idx = i
            prompt = before + "#"
            break
    if echo_idx is None:
        raise CliTransportError(
            "command echo not found in SSH transcript: %r" % command)
    body = []
    for line in lines[echo_idx + 1:]:
        if line.startswith(prompt):       # next prompt -> end of this output
            break
        body.append(line)
    return "\n".join(body).rstrip("\n")


class SSHCli(object):
    """Guest-Shell-`cli`-compatible transport over an SSH-to-self IOS session.

    Commands and SCP transfers reuse an OpenSSH control connection for a short
    time. A single agent tick makes several IOS calls (filesystem checks,
    transfer, copy /verify, telemetry); reconnecting per call creates a login
    storm on the device. The login may land at priv-1 or priv-15; each CLI
    channel still sends `enable` + the enable secret before its command.

    `runner(script:str) -> transcript:str` is injectable for unit tests; the
    default shells out to sshpass+ssh with the legacy kex/cipher options these
    IOS-XE boxes require (same set lab/device-run.sh uses)."""

    def __init__(self, host, user, password=None, enable=None, port=22,
                 runner=None, scp_runner=None, connect_timeout=15,
                 exec_timeout=900, control_path=None, known_hosts=None):
        self.host = host
        self.user = user
        self.password = password
        # default the enable secret to the login password (lab convention)
        self.enable = enable if enable is not None else password
        self.port = int(port)
        self.connect_timeout = int(connect_timeout)
        self.exec_timeout = int(exec_timeout)
        self.known_hosts = known_hosts
        stage_dir = os.environ.get("IRIS_STAGE_DIR", "/tmp")
        self.control_path = control_path or os.path.join(
            stage_dir, "ios-ssh-%r@%h:%p")
        self._runner = runner or self._default_runner
        self._scp = scp_runner or self._default_scp

    def _hostkey_options(self):
        # verify-if-present, same shape as make_catalog_context's TLS pinning
        # (spec §4.6): when a known_hosts file is configured AND exists, pin the
        # device host key against it; otherwise keep the legacy no-verify pair
        # unchanged, so a fleet whose conf has no pin behaves identically after
        # an agent-only upgrade. The no-verify default is tolerable only because
        # this is SSH-to-self over the app's point-to-point /30 to the switch's
        # own SVI — same posture as lab/device-run.sh.
        if self.known_hosts and os.path.exists(self.known_hosts):
            return ["-o", "StrictHostKeyChecking=yes",
                    "-o", "UserKnownHostsFile=" + self.known_hosts]
        return ["-o", "StrictHostKeyChecking=no",
                "-o", "UserKnownHostsFile=/dev/null"]

    def _control_options(self):
        # ControlPath substitutions (%r/%h/%p) keep each IOS target separate.
        # ControlPersist reaps the master after the agent has been idle, so an
        # app restart or target change does not leave a permanent connection.
        return ["-o", "ControlMaster=auto", "-o", "ControlPersist=120",
                "-o", "ControlPath=" + self.control_path]

    def _exec_script(self, cmd):
        # enable -> secret -> disable paging/wrapping -> the command -> log out.
        # `terminal width 0` is defensive: keep long `show file systems` / `dir`
        # rows from soft-wrapping (which would corrupt the text-exact parsers).
        return "enable\n%s\nterminal length 0\nterminal width 0\n%s\nexit\n" % (
            self.enable or "", cmd)

    def _config_script(self, lines):
        return "enable\n%s\nconfigure terminal\n%s\nend\nexit\n" % (
            self.enable or "", "\n".join(lines))

    def execute(self, cmd):
        try:
            transcript = self._runner(self._exec_script(cmd))
        except Exception as e:
            raise CliTransportError("ssh transport failed: %s" % e)
        return extract_output(transcript, cmd)

    def configure(self, lines):
        # Guest Shell `cli.configure` returns nothing the agent uses; callers
        # ignore the result. Apply the block and surface only transport failure
        # (config-level `% ...` messages -- e.g. removing an absent applet --
        # are benign, exactly as on the Guest Shell path).
        try:
            self._runner(self._config_script(list(lines)))
        except Exception as e:
            raise CliTransportError("ssh transport failed: %s" % e)
        return None

    def put(self, local_path, remote_dest):
        """scp a local file to the device (container -> device — the proven
        direction; IOx can't bind-mount sdflash: and inbound to the container is
        blocked). `remote_dest` is an IOS path, e.g. 'sdflash:guest-share/iris/
        cat9k.bin'. This is how the IOx-app agent lands its downloaded scratch on
        the IOS-visible SD so `copy /verify` can place it — the IE3x00 analog of
        the C9300 writing the scratch via the guestshell mount."""
        target = "%s@%s:%s" % (self.user, self.host, remote_dest)
        try:
            self._scp(local_path, target)
        except Exception as e:
            raise CliTransportError("scp push failed: %s" % e)

    def _default_scp(self, local_path, target):  # pragma: no cover (shells out)
        cmd = [
            "sshpass", "-e", "scp",
            "-O",                       # legacy scp protocol — IOS scp server needs it
        ] + self._hostkey_options() + [
            "-o", "ConnectTimeout=%d" % self.connect_timeout,
            "-o", "KexAlgorithms=+diffie-hellman-group14-sha1,"
                  "diffie-hellman-group-exchange-sha1",
            "-o", "HostKeyAlgorithms=+ssh-rsa",
            "-o", "PubkeyAcceptedAlgorithms=+ssh-rsa",
            "-o", "Ciphers=+aes128-cbc,aes256-cbc,3des-cbc",
            "-P", str(self.port),
        ] + self._control_options() + [local_path, target]
        env = dict(os.environ, SSHPASS=self.password or "")
        subprocess.run(cmd, env=env, check=True, stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL, timeout=self.exec_timeout)

    def _default_runner(self, script):  # pragma: no cover (shells out to ssh)
        cmd = [
            "sshpass", "-e", "ssh", "-tt",
        ] + self._hostkey_options() + [
            "-o", "ConnectTimeout=%d" % self.connect_timeout,
            "-o", "KexAlgorithms=+diffie-hellman-group14-sha1,"
                  "diffie-hellman-group-exchange-sha1",
            "-o", "HostKeyAlgorithms=+ssh-rsa",
            "-o", "PubkeyAcceptedAlgorithms=+ssh-rsa",
            "-o", "Ciphers=+aes128-cbc,aes256-cbc,3des-cbc",
            "-p", str(self.port),
        ] + self._control_options() + ["%s@%s" % (self.user, self.host)]
        env = dict(os.environ, SSHPASS=self.password or "")
        proc = subprocess.run(
            cmd, input=script, env=env,
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            timeout=self.exec_timeout, universal_newlines=True)
        return proc.stdout


def _import_guestshell_cli():  # pragma: no cover (only runs inside Guest Shell)
    from cli import execute, configure
    return execute, configure


def select_cli(cfg, env=None, guestshell_factory=None):
    """Runtime-mode seam. Return `(cli_execute, cli_configure)`.

    container mode (env IRIS_RUNTIME_MODE=container, or conf `runtime_mode =
    container`) -> SSHCli bound methods. Otherwise the Guest Shell `cli` import
    -- the C9300 path, unchanged. Gating on env/conf keeps the guestshell branch
    byte-identical to the original two-line import."""
    env = os.environ if env is None else env
    mode = env.get("IRIS_RUNTIME_MODE") or cfg.get("runtime_mode") or "guestshell"
    if mode == "container":
        cli = SSHCli(
            host=cfg["device_ssh_host"],
            user=cfg["device_ssh_user"],
            password=cfg.get("device_ssh_pass"),
            enable=cfg.get("device_ssh_enable"),
            port=cfg.get("device_ssh_port", 22),
            # optional pinned known_hosts (verify-if-present; see
            # _hostkey_options) — absent on existing fleet confs, so the
            # default stays the legacy no-verify behavior.
            known_hosts=cfg.get("device_ssh_known_hosts"),
        )
        return cli.execute, cli.configure
    if guestshell_factory is None:
        guestshell_factory = _import_guestshell_cli
    return guestshell_factory()
