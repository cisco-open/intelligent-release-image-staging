#!/usr/bin/env bash

# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

# Generate ONE self-contained installer per device from a CSV of network info.
# NO permanent secret is ever baked — secrets are handled automatically:
#   * asks the running `iris` server for a SHORT-LIVED enrollment token per device
#     (iris-mint-enrollment <device_id>, TTL=IRIS_ENROLL_TTL, default 1h); the agent
#     self-promotes it to a full catalog token on its first tick. RPC secret is NOT
#     baked — the agent fetches it on that same first token-refresh.
#   * derives the catalog URL / stage host from IRIS_HOST_IP or this machine's IP
#
# Usage:  tools/gen-device-installers.sh [csv]      (legacy routed inventory only)
# CSV v2 deployment is intentionally Console/API-only: it requires a persisted
# receipt, plan confirmation, and preflight before an enrollment token is minted.
# Output: fleet/dist/install-<device_id>.sh  (+ install-all.sh)
set -euo pipefail
REPO="$(cd "$(dirname "$0")/.." && pwd)"
CSV="${1:-$REPO/fleet/devices.csv}"
OUT="${OUT:-$REPO/fleet/dist}"
[ -f "$CSV" ] || { echo "no CSV inventory: $CSV (copy fleet/devices.csv.example)" >&2; exit 1; }
if IFS= read -r first_line < "$CSV" && [[ "$first_line" == *"network_attachment"* ]]; then
  echo "ERROR: CSV v2 requires Console/API onboarding so IRIS can persist a receipt,"
  echo "plan, and preflight before minting an enrollment token." >&2
  exit 1
fi

# ---------- where do the server's secrets live? ----------
in_docker() { docker ps --format '{{.Names}}' 2>/dev/null | grep -qx iris; }
cfg_read()  {  # cfg_read <file>
  if in_docker; then docker exec iris cat "/etc/iris/$1" 2>/dev/null
  elif [ -r "/etc/iris/$1" ]; then cat "/etc/iris/$1"
  else return 1; fi
}
# The BARE server cert (tls/crt.pem, NOT the combined tls/cert.pem+key — never ship
# the key). Threaded into each installer for the on-device PKI trustpoint + curl
# --cacert (#2). cfg_read reads /etc/iris/<arg>, so the arg is tls/crt.pem.
IRIS_CRT="$(cfg_read tls/crt.pem || true)"
[ -n "$IRIS_CRT" ] || { echo "ERROR: can't read the server's tls/crt.pem — is the iris container (or bare-metal install) running on this machine?" >&2; exit 1; }

HOST_IP="${IRIS_HOST_IP:-$(hostname -I 2>/dev/null | awk '{print $1}')}"
[ -n "$HOST_IP" ] || { echo "ERROR: set IRIS_HOST_IP=<this server's IP>" >&2; exit 1; }
CATALOG_URL="${CATALOG_URL:-https://$HOST_IP:8443}"
STAGE_HOST="${STAGE_HOST:-$HOST_IP}"

# ---------- per-device ENROLLMENT token ----------
# No permanent secret is ever baked. We ask the running server for a SHORT-LIVED
# enrollment token (scope:catalog, TTL=IRIS_ENROLL_TTL, default 1h); the agent
# self-promotes it to a full 7-day catalog token on its first tick via
# POST /v1/devices/<id>/token-refresh. If it leaks, it expires in an hour.
mint_enrollment() {  # mint_enrollment <device_id> -> prints a fresh enrollment token
  local sid="$1" tok
  if in_docker; then
    tok="$(docker exec iris iris-mint-enrollment "$sid")"
  elif command -v iris-mint-enrollment >/dev/null 2>&1; then
    tok="$(iris-mint-enrollment "$sid")"
  else
    echo "ERROR: can't reach iris-mint-enrollment — is the iris container (or bare-metal install) running on this machine?" >&2
    exit 1
  fi
  [ -n "$tok" ] || { echo "ERROR: iris-mint-enrollment returned an empty token for $sid" >&2; exit 1; }
  printf '%s' "$tok"
}

# ---------- generate ----------
mkdir -p "$OUT"
ALL="$OUT/install-all.sh"
{ echo "#!/usr/bin/env bash"; echo "set -e"; echo 'HERE="$(cd "$(dirname "$0")" && pwd)"'; } > "$ALL"

trim() { echo "$1" | tr -d ' \r'; }
n=0
while IFS=, read -r device_id device_ip vlan svi_ip svi_mask guest_ip csv_token _rest || [ -n "$device_id" ]; do
  device_id="$(trim "$device_id")"
  [ -z "$device_id" ] && continue
  [ "$device_id" = "device_id" ] && continue
  case "$device_id" in \#*) continue;; esac
  device_ip="$(trim "$device_ip")"; vlan="$(trim "$vlan")"
  svi_ip="$(trim "$svi_ip")"; svi_mask="$(trim "$svi_mask")"; guest_ip="$(trim "$guest_ip")"
  tok="$(trim "${csv_token:-}")"
  [ -n "$tok" ] || tok="$(mint_enrollment "$device_id")"

  f="$OUT/install-$device_id.sh"
  cat > "$f" <<EOF
#!/usr/bin/env bash
# IRIS installer for device $device_id  (GENERATED — re-run the generator to change)
set -euo pipefail
REPO="\$(cd "\$(dirname "\$0")/../.." && pwd)"
export DEVICE_IP="$device_ip" VLAN="$vlan" SVI_IP="$svi_ip" SVI_MASK="$svi_mask" GUEST_IP="$guest_ip" DEVICE_ID="$device_id"
export CATALOG_URL="$CATALOG_URL" CATALOG_TOKEN="$tok"
export STAGE_HOST="$STAGE_HOST"
# exported empty so device-install.sh reads a defined (empty) value; the agent fetches the real rpc_secret on its first token-refresh.
export RPC_SECRET=""
# Materialize the server's BARE cert (crt.pem) to a temp file and hand its path to
# the installer for the on-device PKI trustpoint + curl --cacert (#2). Removed on exit.
# NOT exec'd: keep this shell alive so the EXIT trap can remove the temp cert.
IRIS_CRT_FILE="\$(mktemp "\${TMPDIR:-/tmp}/iris-crt.XXXXXX")"
trap 'rm -f "\$IRIS_CRT_FILE"' EXIT
cat > "\$IRIS_CRT_FILE" <<'IRIS_PEM'
$IRIS_CRT
IRIS_PEM
export IRIS_CRT_FILE
bash "\$REPO/device/device-install.sh" "\$@"
EOF
  chmod +x "$f"
  echo "\"\$HERE/install-$device_id.sh\" \"\$@\"" >> "$ALL"
  echo "  generated $f"
  n=$((n + 1))
done < "$CSV"
chmod +x "$ALL"
echo "Done: $n per-device installer(s) in $OUT/  (run one, or fleet/dist/install-all.sh)"
