# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0
"""CLI to set/reset the web console admin password before the first-run wizard
exists (and for break-glass ops afterwards). Reads the password from
IRIS_GUI_ADMIN_PASSWORD if set, else prompts. Persists via GuiApp (encrypted at
rest when IRIS_AGE_RECIPIENTS is set)."""
import getpass
import os
import sys

import gui_app


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if len(argv) != 1:
        print("usage: iris-gui-admin <username>", file=sys.stderr)
        return 2
    username = argv[0]
    password = os.environ.get("IRIS_GUI_ADMIN_PASSWORD")
    if not password:
        password = getpass.getpass("New admin password: ")
        if password != getpass.getpass("Confirm password: "):
            print("passwords do not match", file=sys.stderr)
            return 1
    if not password:
        print("empty password", file=sys.stderr)
        return 1
    app = gui_app.GuiApp(
        os.environ.get("IRIS_SECRETS", "/run/iris/secrets.json"),
        recipients_csv=os.environ.get("IRIS_AGE_RECIPIENTS") or None,
        secrets_enc=os.environ.get("IRIS_SECRETS_ENC", "/etc/iris/secrets.json.age"),
    )
    app.set_admin(username, password)
    print("admin '%s' set" % username)
    return 0
