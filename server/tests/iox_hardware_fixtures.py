# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Verbatim IOS-XE output recorded from lab hardware on 2026-09-10.

Every byte string in this module was copied out of a transcript the IOx
transport persisted under /var/lib/iris/iox/transcripts during the
2026-09-10 lab runs -- the runs that exposed the dialects listed in issue
#226. The transport stores its NORMALISED capture (CRLF folded to LF,
configured credentials already replaced by ``<redacted>``), so these are the
exact bytes the classifiers in server/iox_transport.py and
server/iox_verification.py saw on the day. Nothing here is typed from
memory or from documentation; where a snippet is an excerpt of a longer
reply the comment says so, and the elided lines are simply absent (no
marker line is invented in their place).

Provenance -- transcript id prefix, command id(s), UTC time:

  IE-3400-8T2S, IOS-XE 17.15.4, hostname 3400-1, board FCW2716Y9J4
    49aeb55a cmd 4                       05:37  unfiltered verification read
    9eaa797c cmd 1,5,8,9,11-14,19-33     06:09  first successful install
    1ac1cee1 cmd 3-5                     06:19  teardown of a running app
    7cc6dc12 cmd 7                       06:46  teardown, SVI already absent
    8f972895 cmd 3-11                    07:04  complete recorded undeploy
    b7d4c09b cmd 7                       10:55  forced teardown, no discriminator

  Catalyst 8000V, IOS-XE 17.15.5, hostnames iris-c8kv-101..104,
  boards 97XHUO6BK8W / 9NV64Y4FKZI / 9M2OJSX7LS9 / 9BTKNF1NCMS
    ad6e0e07 cmd 1,10-13                 07:26  disable verdict before bc4e5f2
    2172659f cmd 20                      09:41  IOxMan refuses the app block
    a66eb0d1 cmd 3                       10:35  preflight with the app RUNNING
    46969801 cmd 7                       10:55  forced teardown, no discriminator
    dc5528b3 cmd 5,6,8,14-16,22-36       12:36  complete install
    e260c239 cmd 6-8,10,11               13:13  complete undeploy

Only IRIS-relevant excerpts of `show version` and `show running-config`
are kept. A device's full running configuration carries its local
credential hashes and is never copied here.

Each *_STEPS table pairs a command line exactly as IRIS sent it with the
payload IOS returned for it, in order, so a fake peer can replay the
exchange. The payloads were cross-checked against the transport's own
recorded payload spans wherever the command's framing completed.
"""

# ---------------------------------------------------------------------------
# Prompts and session diagnostics
# ---------------------------------------------------------------------------

IE3400_HOST = "3400-1"
IE3400_BOARD = "FCW2716Y9J4"
C8000V_HOST = "iris-c8kv-104"
C8000V_BOARD = "97XHUO6BK8W"

# ssh's own close notice on stderr, with returncode 0. The C8000V adds the
# "closed by remote host" line on most sessions; the IE-3400 never did.
IE3400_SSH_STDERR = b'Connection to 100.90.168.99 closed.\n'
C8000V_SSH_STDERR = (b'Connection to 100.90.170.104 closed by remote host.\n'
                     b'Connection to 100.90.170.104 closed.\n')
C8000V_SSH_STDERR_101 = (b'Connection to 100.90.170.101 closed by remote host.\n'
                         b'Connection to 100.90.170.101 closed.\n')
# scp's stderr on a successful wrapper upload (dc5528b3 cmd 6, rc 0).
C8000V_SCP_STDERR = b'Connection to 100.90.170.104 closed by remote host.\n'

CONFIG_BANNER = b'Enter configuration commands, one per line.  End with CNTL/Z.\n'

# ---------------------------------------------------------------------------
# Identity: `show version` excerpts (9eaa797c cmd 1; ad6e0e07 cmd 1)
# ---------------------------------------------------------------------------

# Excerpt: the two version header lines, then the identity block. The
# IE-3400 carries a "Model Number" line; the C8000V does not.
IE3400_SHOW_VERSION = (
    b"Cisco IOS XE Software, Version 17.15.04\n"
    b"Cisco IOS Software [IOSXE], IE3x00 Switch Software (IE3x00-UNIVERSALK9-M), Version 17.15.4, RELEASE SOFTWARE (fc6)\n"
    b"cisco IE-3400-8T2S (ARM) processor (revision V06) with 649067K/6147K bytes of memory.\n"
    b"Processor board ID FCW2716Y9J4\n"
    b"3 Virtual Ethernet interfaces\n"
    b"10 Gigabit Ethernet interfaces\n"
    b"32768K bytes of non-volatile configuration memory.\n"
    b"3950148K bytes of physical memory.\n"
    b"523264K bytes of crashinfo at crashinfo:.\n"
    b"1684480K bytes of Flash at flash:.\n"
    b"9457664K bytes of sdflash at sdflash:.\n"
    b"\n"
    b"Model Number                       : IE-3400-8T2S\n"
    b"System Serial Number               : FCW2716Y9J4\n"
)
C8000V_SHOW_VERSION = (
    b"Cisco IOS XE Software, Version 17.15.05\n"
    b"Cisco IOS Software [IOSXE], Virtual XE Software (X86_64_LINUX_IOSD-UNIVERSALK9-M), Version 17.15.5, RELEASE SOFTWARE (fc3)\n"
    b"cisco C8000V (VXE) processor (revision VXE) with 1890892K/3075K bytes of memory.\n"
    b"Processor board ID 97XHUO6BK8W\n"
    b"Router operating mode: Autonomous\n"
    b"1 Gigabit Ethernet interface\n"
    b"32768K bytes of non-volatile configuration memory.\n"
    b"8082792K bytes of physical memory.\n"
    b"5234688K bytes of virtual hard disk at bootflash:.\n"
    b"\n"
    b"Configuration register is 0x2102\n"
)

# ---------------------------------------------------------------------------
# Status and prerequisite reads
# ---------------------------------------------------------------------------

# `show iox`: the IE-3400 runs Dockerd, the C8000V (KVM-based IOx) only
# Libvirtd. Trailing spaces after "Not Supported" / "Running" are IOS's.
IE3400_IOX_STATUS_STEPS = (
    (b'show iox', b'\nIOx Infrastructure Summary:\n---------------------------\nIOx service (CAF)              : Running\nIOx service (HA)               : Not Supported \nIOx service (IOxman)           : Running \nIOx service (Sec storage)      : Running \nLibvirtd 5.5.0                 : Running\nDockerd v19.03.13-ce           : Running\n\n'),
)
C8000V_IOX_STATUS_STEPS = (
    (b'show iox', b'\nIOx Infrastructure Summary:\n---------------------------\nIOx service (CAF)              : Running\nIOx service (HA)               : Not Supported \nIOx service (IOxman)           : Running \nIOx service (Sec storage)      : Not Supported \nLibvirtd 5.5.0                 : Running\n\n'),
)
IE3400_STORAGE_PREREQ_STEPS = (
    (b'show sdflash: filesys', b'Filesystem: sdflash\nFilesystem Path: /flash12\nFilesystem Type: vfat\nMounted: Read/Write\n\nIOx Partition Exists\nIOx Partition Type: ext4\nIOx Partition Path: /flash11\nIOx Partition Size: 20.7 G\nIOS Partition Size: 9.0 G\n\n'),
)
IE3400_ROUTING_PREREQ_STEPS = (
    (b'show running-config | include no ip routing', b''),
    (b'show ip route | include Gateway|Default gateway', b'Gateway of last resort is 100.90.168.1 to network 0.0.0.0\n'),
)
C8000V_ROUTING_PREREQ_STEPS = (
    (b'show ip interface brief', b'Interface              IP-Address      OK? Method Status                Protocol\nGigabitEthernet1       100.90.170.104  YES NVRAM  up                    up      \n'),
)

# ---------------------------------------------------------------------------
# Verification grammar
# ---------------------------------------------------------------------------

VERIFY_READ_COMMAND = b'show app-hosting infra | include App signature verification'
VERIFY_READ_ENABLED = b'App signature verification: enabled\n'
VERIFY_READ_DISABLED = b'App signature verification: disabled\n'
# What the UNFILTERED `show app-hosting infra` returns on the IE-3400
# (49aeb55a cmd 4): the whole block, which the closed grammar can never
# accept -- every install read as readback_unknown until fa92bf1 filtered
# the command to the one field.
IE3400_VERIFY_READ_UNFILTERED = b'IOX version: 2.12.0.3\nApp signature verification: disabled\nCAF Health: Stable\nInternal working directory: /flash11/iox\n\nApplication Interface Mapping\nAppGigabitEthernet Port #  Interface Name                 Port Type            Bandwidth  \n           1               VirtEth                        KR Port - Internal   1G\n        \n\nCPU:\n  Quota: 33(Percentage) \n  Available: 33(Percentage)\n  Quota: 1400(Units)\n  Available: 1400(Units)\n\n'
# The C8000V's transition wording ("App signature ..." where the IE-3x00
# says "App hosting ..."), each followed by a blank line.
C8000V_VERIFY_DISABLED = b'App signature verification disabled successfully\n\n'
C8000V_VERIFY_ENABLED = b'App signature verification enabled successfully\n\n'
# The complete stdout and the recorded end fields of ad6e0e07 cmd 12, the
# verification_disable classified two minutes BEFORE bc4e5f2 taught the
# classifier the C8000V wording: stored as transition "other" with
# error_category "unsupported_response". Loading this record with a
# classifier that now says "disabled_successfully" is issue #227.
C8000V_VERIFY_DISABLE_STDOUT = b'\n\niris-c8kv-101#terminal length 0\niris-c8kv-101#terminal width 512\niris-c8kv-101#app-hosting verification disable\nApp signature verification disabled successfully\n\niris-c8kv-101#exit\n'
C8000V_VERIFY_DISABLE_RECORDED = {
    "returncode": 0, "framing_complete": True,
    "error_category": "unsupported_response",
    "observed_state": None, "transition_response": "other",
    "payload_spans": [{"offset": 114, "length": 50}],
    "stdout_observed_bytes": 183, "stderr_observed_bytes": 89,
}

# ---------------------------------------------------------------------------
# Configuration steps
# ---------------------------------------------------------------------------

# `iox` on the IE-3400 answers with an advisory; the C8000V is silent.
IE3400_IOX_WARNING = b'Warning: Do not remove SD flash card when IOx is enabled or errors on SD device could occur.\n\n'
IE3400_PREPARE_IOX_SCP_STEPS = (
    (b'configure terminal', CONFIG_BANNER),
    (b'iox', IE3400_IOX_WARNING),
    (b'file prompt quiet', b''),
    (b'ip scp server enable', b''),
    (b'end', b''),
)
C8000V_PREPARE_IOX_SCP_STEPS = (
    (b'configure terminal', CONFIG_BANNER),
    (b'iox', b''),
    (b'file prompt quiet', b''),
    (b'ip scp server enable', b''),
    (b'end', b''),
)

# IOxMan on a C8000V refusing the app block after an earlier undeploy left
# the resource-profile association behind (issue #230); every line of the
# block then fails as invalid input because the sub-mode was never
# entered. 2172659f cmd 20 sent the whole block; this is its first six
# lines plus the `end` the batch closes with.
C8000V_RESOURCE_PROFILE_REFUSAL = b'% node--1:dbm:IOxMan:Resource Profile-names is not specified\n'
C8000V_CONFIGURE_APP_REFUSED_STEPS = (
    (b'configure terminal', CONFIG_BANNER),
    (b'app-hosting appid iris', C8000V_RESOURCE_PROFILE_REFUSAL),
    (b' app-vnic gateway0 virtualportgroup 1 guest-interface 0', b"                           ^\n% Invalid input detected at '^' marker.\n\n"),
    (b'  guest-ipaddress 100.90.171.14 netmask 255.255.255.252', b"                         ^\n% Invalid input detected at '^' marker.\n\n"),
    (b' app-default-gateway 100.90.171.13 guest-interface 0', b"                           ^\n% Invalid input detected at '^' marker.\n\n"),
    (b' app-resource profile custom', b"                           ^\n% Invalid input detected at '^' marker.\n\n"),
    (b'end', b''),
)

# ---------------------------------------------------------------------------
# Lifecycle verbs
# ---------------------------------------------------------------------------

# An absent app, in the two spellings IOS uses (identical on both platforms).
APP_ABSENT_STOP = b'% Error: The application: iris, does not exist\n\n'
APP_ABSENT_UNINSTALL = b"% Error: No App found with name 'iris'\n\n"
# A wrong-state verb is refused WITHOUT a '%' prefix (8f972895 cmd 3-4).
IE3400_STOP_DEPLOYED = b"Invalid 'stop' request. iris is in DEPLOYED\n\n"
IE3400_DEACTIVATE_DEPLOYED = b"Invalid 'deactivate' request. iris is in DEPLOYED\n\n"
# The verbs succeeding on a running app (1ac1cee1 cmd 3-5).
IE3400_STOPPED = b'iris stopped successfully\nCurrent state is: STOPPED\n'
IE3400_DEACTIVATED = b'iris deactivated successfully\nCurrent state is: DEPLOYED\n\n'
UNINSTALLING = b"Uninstalling 'iris'. Use 'show app-hosting list' for progress.\n\n"
IE3400_INSTALL_COMMAND = b'app-hosting install appid iris package flash:iris-872886fb9c2efbe257b09299f73320ee.tar'
IE3400_INSTALLING = b"Installing package 'flash:iris-872886fb9c2efbe257b09299f73320ee.tar' for 'iris'. Use 'show app-hosting list' for progress.\n\n"
ACTIVATED = b'iris activated successfully\nCurrent state is: ACTIVATED\n\n'
STARTED = b'iris started successfully\nCurrent state is: RUNNING\n'
C8000V_COPY_CERTIFICATE_COMMAND = b'app-hosting data appid iris copy bootflash:iris-ca.pem iris-catalog.pem'
C8000V_COPY_CERTIFICATE = b'Successfully copied file /bootflash/iris-ca.pem to iris as iris-catalog.pem\n'

# `show app-hosting list`: the same table on both platforms.
APP_LIST_EMPTY = b'No App found\n\n'
APP_LIST = {
    "INSTALLING": b'App id                                   State\n---------------------------------------------------------\niris                                     INSTALLING\n\n',
    "DEPLOYED": b'App id                                   State\n---------------------------------------------------------\niris                                     DEPLOYED\n\n',
    "ACTIVATED": b'App id                                   State\n---------------------------------------------------------\niris                                     ACTIVATED\n\n',
    "RUNNING": b'App id                                   State\n---------------------------------------------------------\niris                                     RUNNING\n\n',
}

# ---------------------------------------------------------------------------
# Install preflight (a66eb0d1 cmd 3; ad6e0e07 cmd 3)
# ---------------------------------------------------------------------------

# The preflight sends `show app-hosting list` and `show running-config` in
# one session and parses the WHOLE capture, echoes included. These are the
# recorded frame of a66eb0d1 cmd 3 and the two IRIS stanzas its running
# configuration carried, so a test can compose the three app-list states
# around the recorded configuration. Elided: everything in the
# configuration that is not IRIS's, and the two run-opts lines that carry
# the device password and catalog token (stored as <redacted>).
_C8000V_PREFLIGHT_HEAD = (
    b'\n\niris-c8kv-101#terminal length 0\niris-c8kv-101#terminal width 512\n'
    b'iris-c8kv-101#show app-hosting list\n'
)
_C8000V_PREFLIGHT_CONFIG_HEAD = (
    b'iris-c8kv-101#show running-config\n'
    b'Building configuration...\n'
    b'\n'
    b'Current configuration : 6622 bytes\n'
    b'!\n'
    b'! Last configuration change at 10:29:48 UTC Thu Sep 10 2026 by dnac\n'
    b'!\n'
    b'version 17.15\n'
    b'hostname iris-c8kv-101\n'
    b'!\n'
)
C8000V_VPG_STANZA = (
    b'interface VirtualPortGroup1\n'
    b' description IRIS IOx VPG\n'
    b' ip address 100.90.171.1 255.255.255.252\n'
    b'!\n'
)
C8000V_APP_STANZA = (
    b'app-hosting appid iris\n'
    b' app-vnic gateway0 virtualportgroup 1 guest-interface 0\n'
    b'  guest-ipaddress 100.90.171.2 netmask 255.255.255.252\n'
    b' app-default-gateway 100.90.171.1 guest-interface 0\n'
    b' app-resource docker\n'
    b'  run-opts 1 "-e IRIS_DEVICE_ID=Iris-c8kv-101"\n'
    b'  run-opts 4 "-e IRIS_CATALOG_URL=https://100.90.168.20:8443"\n'
    b'  run-opts 5 "-e IRIS_DEVICE_SSH_HOST=100.90.171.1"\n'
    b'  run-opts 6 "-e IRIS_DEVICE_SSH_USER=dnac"\n'
    b'  run-opts 7 "-e IRIS_DEVICE_PLATFORM=iox"\n'
    b'  run-opts 8 "-e IRIS_TARGET_FS=bootflash:"\n'
    b'  run-opts 9 "-e IRIS_TELEMETRY=on"\n'
    b'  run-opts 10 "-e IRIS_TELEMETRY_STREAM=off"\n'
    b'  run-opts 11 "-e IRIS_LOG=off"\n'
    b' app-resource profile custom\n'
    b'  cpu 400\n'
    b'  memory 768\n'
    b'  persist-disk 2048\n'
    b'  vcpu 1\n'
)
_C8000V_PREFLIGHT_TAIL = b'end\n\niris-c8kv-101#exit\n'


def c8000v_preflight(app_list, *stanzas):
    """The preflight capture with *app_list* in the app-list slot and the
    given IRIS stanzas in the running configuration."""
    return (_C8000V_PREFLIGHT_HEAD + app_list + _C8000V_PREFLIGHT_CONFIG_HEAD +
            b"".join(stanzas) + _C8000V_PREFLIGHT_TAIL)


# ---------------------------------------------------------------------------
# Teardown: configuration
# ---------------------------------------------------------------------------

EEM_ABSENT = (
    b'%EEM: No such applet IRIS-AGENT\n',
    b'%EEM: No such applet IRIS-COPYROOT\n',
    b'%EEM: No such applet IRIS-RECLAIM\n',
    b'%EEM: No such applet IRIS-RECLAIM-BUNDLE\n',
)
TRUSTPOINT_ABSENT = b'% There is no "IRIS" trustpoint to delete.\n'
POLICY_ABSENT = b"% Can't find policy IRIS\n\n"
# `no logging discriminator IRISQ` without one: no '%' prefix.
DISCRIMINATOR_ABSENT = b'Specified MD by the name IRISQ does not exist.\n\n'
# `no interface Vlan666` for an absent SVI: the same reply as a syntax
# error, caret line included (7cc6dc12 cmd 7).
IE3400_VLAN_ABSENT_INVALID_INPUT = b"                             ^\n% Invalid input detected at '^' marker.\n\n"

# 8f972895 cmd 7: the switch teardown with the app already gone.
IE3400_CLEANUP_CONFIG_STEPS = (
    (b'configure terminal', CONFIG_BANNER),
    (b'no app-hosting appid iris', b''),
    (b'no event manager applet IRIS-AGENT', EEM_ABSENT[0]),
    (b'no event manager applet IRIS-COPYROOT', EEM_ABSENT[1]),
    (b'no event manager applet IRIS-RECLAIM', EEM_ABSENT[2]),
    (b'no event manager applet IRIS-RECLAIM-BUNDLE', EEM_ABSENT[3]),
    (b'no interface Vlan666', b''),
    (b'no vlan 666', b''),
    (b'no ip http client secure-trustpoint IRIS', TRUSTPOINT_ABSENT),
    (b'no crypto pki trustpoint IRIS', POLICY_ABSENT),
    (b'end', b''),
)
IE3400_CLEANUP_CONFIG_STDOUT = b'\n\n3400-1#terminal length 0\n3400-1#terminal width 512\n3400-1#configure terminal\nEnter configuration commands, one per line.  End with CNTL/Z.\n3400-1(config)#no app-hosting appid iris\n3400-1(config)#no event manager applet IRIS-AGENT\n%EEM: No such applet IRIS-AGENT\n3400-1(config)#no event manager applet IRIS-COPYROOT\n%EEM: No such applet IRIS-COPYROOT\n3400-1(config)#no event manager applet IRIS-RECLAIM\n%EEM: No such applet IRIS-RECLAIM\n3400-1(config)#no event manager applet IRIS-RECLAIM-BUNDLE\n%EEM: No such applet IRIS-RECLAIM-BUNDLE\n3400-1(config)#no interface Vlan666\n3400-1(config)#no vlan 666\n3400-1(config)#no ip http client secure-trustpoint IRIS\n% There is no "IRIS" trustpoint to delete.\n3400-1(config)#no crypto pki trustpoint IRIS\n% Can\'t find policy IRIS\n\n3400-1(config)#end\n3400-1#exit\n'
# 7cc6dc12 cmd 7: the same teardown with the SVI already removed.
IE3400_CLEANUP_CONFIG_ABSENT_VLAN_STEPS = (
    (b'configure terminal', CONFIG_BANNER),
    (b'no app-hosting appid iris', b''),
    (b'no event manager applet IRIS-AGENT', EEM_ABSENT[0]),
    (b'no event manager applet IRIS-COPYROOT', EEM_ABSENT[1]),
    (b'no event manager applet IRIS-RECLAIM', EEM_ABSENT[2]),
    (b'no event manager applet IRIS-RECLAIM-BUNDLE', EEM_ABSENT[3]),
    (b'no interface Vlan666', IE3400_VLAN_ABSENT_INVALID_INPUT),
    (b'no vlan 666', b''),
    (b'no ip http client secure-trustpoint IRIS', TRUSTPOINT_ABSENT),
    (b'no crypto pki trustpoint IRIS', POLICY_ABSENT),
    (b'end', b''),
)
# e260c239 cmd 7: the router teardown after f75622f, which empties the app
# block before removing it (VirtualPortGroup vnic on a router).
C8000V_CLEANUP_CONFIG_STEPS = (
    (b'configure terminal', CONFIG_BANNER),
    (b'app-hosting appid iris', b''),
    (b' no app-resource docker', b''),
    (b' no app-resource profile custom', b''),
    (b' no app-default-gateway 100.90.171.9 guest-interface 0', b''),
    (b' no app-vnic gateway0 virtualportgroup 1 guest-interface 0', b''),
    (b'exit', b''),
    (b'no app-hosting appid iris', b''),
    (b'no event manager applet IRIS-AGENT', EEM_ABSENT[0]),
    (b'no event manager applet IRIS-COPYROOT', EEM_ABSENT[1]),
    (b'no event manager applet IRIS-RECLAIM', EEM_ABSENT[2]),
    (b'no event manager applet IRIS-RECLAIM-BUNDLE', EEM_ABSENT[3]),
    (b'no interface VirtualPortGroup1', b''),
    (b'no ip http client secure-trustpoint IRIS', TRUSTPOINT_ABSENT),
    (b'no crypto pki trustpoint IRIS', POLICY_ABSENT),
    (b'end', b''),
)
# The forced teardowns of 10:55 (b7d4c09b on the switch, 46969801 on the
# router) ran BEFORE 54fea1f taught the classifier the discriminator
# notice, so the transport killed each session (rc -15) right after it:
# these are the recorded lines up to that point. The recipe's remaining
# lines were never sent, so a replay closes the batch with its own `end`.
IE3400_FORCED_TEARDOWN_PREFIX = (
    (b'configure terminal', CONFIG_BANNER),
    (b'app-hosting appid iris', b''),
    (b' no app-resource docker', b''),
    (b' no app-resource profile custom', b''),
    (b' no app-default-gateway 100.92.100.253 guest-interface 0', b''),
    (b' no app-vnic AppGigabitEthernet trunk', b''),
    (b'exit', b''),
    (b'no app-hosting appid iris', b''),
    (b'no event manager applet IRIS-AGENT', EEM_ABSENT[0]),
    (b'no event manager applet IRIS-COPYROOT', EEM_ABSENT[1]),
    (b'no event manager applet IRIS-RECLAIM', EEM_ABSENT[2]),
    (b'no event manager applet IRIS-RECLAIM-BUNDLE', EEM_ABSENT[3]),
    (b'no logging buffered discriminator IRISQ', b''),
    (b'no logging console discriminator IRISQ', b''),
    (b'no logging monitor discriminator IRISQ', b''),
    (b'no logging discriminator IRISQ', DISCRIMINATOR_ABSENT),
)
C8000V_FORCED_TEARDOWN_PREFIX = (
    (b'configure terminal', CONFIG_BANNER),
    (b'app-hosting appid iris', b''),
    (b' no app-resource docker', b''),
    (b' no app-resource profile custom', b''),
    (b' no app-default-gateway 100.90.171.5 guest-interface 0', b''),
    (b' no app-vnic gateway0 virtualportgroup 1 guest-interface 0', b''),
    (b'exit', b''),
    (b'no app-hosting appid iris', b''),
    (b'no event manager applet IRIS-AGENT', EEM_ABSENT[0]),
    (b'no event manager applet IRIS-COPYROOT', EEM_ABSENT[1]),
    (b'no event manager applet IRIS-RECLAIM', EEM_ABSENT[2]),
    (b'no event manager applet IRIS-RECLAIM-BUNDLE', EEM_ABSENT[3]),
    (b'no logging buffered discriminator IRISQ', b''),
    (b'no logging console discriminator IRISQ', b''),
    (b'no logging monitor discriminator IRISQ', b''),
    (b'no logging discriminator IRISQ', DISCRIMINATOR_ABSENT),
)

# ---------------------------------------------------------------------------
# Teardown: files, probes, save
# ---------------------------------------------------------------------------

IE3400_CLEANUP_FILES_STEPS = (
    (b'delete /force flash:iris-arm64.tar', b'%Error deleting flash:iris-arm64.tar (No such file or directory)\n'),
    (b'delete /force flash:iris-ca.pem', b'%Error deleting flash:iris-ca.pem (No such file or directory)\n'),
    (b'delete /force flash:iris-catalog.pem', b'%Error deleting flash:iris-catalog.pem (No such file or directory)\n'),
    (b'delete /force /recursive sdflash:guest-share/iris', b''),
)
C8000V_CLEANUP_FILES_STEPS = (
    (b'delete /force bootflash:iris-amd64.tar', b'%Error deleting bootflash:iris-amd64.tar (No such file or directory)\n'),
    (b'delete /force bootflash:iris-ca.pem', b'%Error deleting bootflash:iris-ca.pem (No such file or directory)\n'),
    (b'delete /force bootflash:iris-catalog.pem', b'%Error deleting bootflash:iris-catalog.pem (No such file or directory)\n'),
    (b'delete /force /recursive bootflash:guest-share/iris', b''),
)
IE3400_CONFIG_PROBE_STEPS = (
    (b'show app-hosting list', APP_LIST_EMPTY),
    (b'show running-config | include app-hosting appid iris|applet IRIS-|crypto pki trustpoint IRIS|discriminator IRISQ|interface Vlan666|^vlan 666$', b''),
)
IE3400_STAGE_PROBE_STEPS = (
    (b'dir flash: | include iris\\-arm64\\.tar|iris-ca\\.pem|iris-catalog\\.pem', b''),
    (b'dir sdflash:guest-share/iris', b'%Error opening sdflash:guest-share/iris (No such file or directory)\n'),
)
C8000V_STAGE_PROBE_STEPS = (
    (b'dir bootflash: | include iris\\-amd64\\.tar|iris-ca\\.pem|iris-catalog\\.pem', b''),
    (b'dir bootflash:guest-share/iris', b'%Error opening bootflash:guest-share/iris (No such file or directory)\n'),
)
# `write memory` on both platforms: the progress line, then the verdict.
SAVE_CONFIRMED = b'Building configuration...\n[OK]\n'
SAVE_STEPS = ((b'write memory', SAVE_CONFIRMED),)

# ---------------------------------------------------------------------------
# Not from an IOx transcript
# ---------------------------------------------------------------------------

# IOS's reply when a line reaches the exec parser as a hostname, recorded
# from a Guest Shell session in device/agent/tests/test_cli_ssh.py (CRLF
# folded as the transport would). No IOx transcript of 2026-09-10 carries
# it; it is here only to pin how the IOx classifiers would read it.
GUESTSHELL_BAD_IP = b'% Bad IP address or host name% Unknown command or computer name, or unable to find computer address\n'
