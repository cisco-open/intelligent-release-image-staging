# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0
#
# Deploy-time env must win over a persistent conf on redeploy (same operator
# intent as the TARGET_FS reconcile in entrypoint.sh): without this, toggling
# telemetry/telemetry_stream via console redeploy silently would not take on
# any device with an existing conf. Sourceable for bats. Expects $CONF; uses
# $PYTHONPATH when set (tests), the container agent path otherwise.
reconcile_conf_key() {
  key="$1"; val="$2"
  [ -n "$val" ] || return 0
  PYTHONPATH="${PYTHONPATH:-/opt/iris/agent}" python3 - "$CONF" "$key" "$val" <<'PY'
import sys
import agent_config
path, key, val = sys.argv[1:]
cfg = agent_config.load(path)
if cfg.get(key) != val:
    cfg[key] = val
    agent_config.write_conf(path, cfg)
PY
}
