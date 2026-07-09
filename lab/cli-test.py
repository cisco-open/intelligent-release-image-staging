#!/usr/bin/env python3

# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Probe whether the Guest Shell `cli` module can emit IOS syslog from a script."""
with open("/home/guestshell/clitest.out", "w") as out:
    try:
        from cli import execute
        execute('send log facility IRIS severity 6 mnemonic SIDTEST '
                '"setsid cli emit test"')
        out.write("CLI_OK\n")
    except Exception as e:
        out.write("CLI_FAIL: %r\n" % e)
