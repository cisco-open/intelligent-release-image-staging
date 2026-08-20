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
if IFS= read -r first_line < "$CSV" && \
   { [[ "$first_line" == *"management_type"* ]] || \
     [[ "$first_line" == *"network_attachment"* ]]; }; then
  echo "ERROR: CSV v2 requires Console/API onboarding so IRIS can persist a receipt,"
  echo "plan, and preflight before minting an enrollment token." >&2
  exit 1
fi

# ---------- where do the server's secrets live? ----------
IRIS_CONTAINER="${IRIS_CONTAINER:-iris}"
in_docker() { docker ps --format '{{.Names}}' 2>/dev/null | grep -qx "$IRIS_CONTAINER"; }
cfg_read()  {  # cfg_read <file>
  in_docker || return 1
  docker exec "$IRIS_CONTAINER" cat "/etc/iris/$1" 2>/dev/null
}
# The BARE server cert (tls/crt.pem, NOT the combined tls/cert.pem+key — never ship
# the key). Threaded into each installer for the on-device PKI trustpoint + curl
# --cacert (#2). cfg_read reads /etc/iris/<arg>, so the arg is tls/crt.pem.
IRIS_CRT="$(cfg_read tls/crt.pem || true)"
[ -n "$IRIS_CRT" ] || { echo "ERROR: can't read the server's tls/crt.pem — is the '$IRIS_CONTAINER' container running on this machine? (set IRIS_CONTAINER=<name> if it is named differently)" >&2; exit 1; }

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
  in_docker || {
    echo "ERROR: can't reach iris-mint-enrollment — is the '$IRIS_CONTAINER' container running on this machine? (set IRIS_CONTAINER=<name> if it is named differently)" >&2
    exit 1
  }
  tok="$(docker exec "$IRIS_CONTAINER" iris-mint-enrollment "$sid")"
  [ -n "$tok" ] || { echo "ERROR: iris-mint-enrollment returned an empty token for $sid" >&2; exit 1; }
  printf '%s' "$tok"
}

# ---------- generate ----------
mkdir -p "$OUT"
ALL="$OUT/install-all.sh"
{ echo "#!/usr/bin/env bash"; echo "set -e"; echo 'HERE="$(cd "$(dirname "$0")" && pwd)"'; } > "$ALL"

trim() { echo "$1" | tr -d ' \r'; }
validate_ipv4() {
  local value="$1" field="$2"
  python3 - "$value" "$field" <<'PY'
import ipaddress
import sys
try:
    ipaddress.IPv4Address(sys.argv[1])
except ipaddress.AddressValueError:
    raise SystemExit("ERROR: %s must be an IPv4 address" % sys.argv[2])
PY
}
validate_field() {
  local value="$1" field="$2" re="$3"
  [[ "$value" =~ $re ]] || { echo "ERROR: $field has an invalid format" >&2; exit 1; }
}
shell_literal() { printf '%q' "$1"; }
n=0
while IFS=, read -r device_id device_ip vlan svi_ip svi_mask guest_ip csv_token _rest || [ -n "$device_id" ]; do
  device_id="$(trim "$device_id")"
  [ -z "$device_id" ] && continue
  [ "$device_id" = "device_id" ] && continue
  case "$device_id" in \#*) continue;; esac
  device_ip="$(trim "$device_ip")"; vlan="$(trim "$vlan")"
  svi_ip="$(trim "$svi_ip")"; svi_mask="$(trim "$svi_mask")"; guest_ip="$(trim "$guest_ip")"
  tok="$(trim "${csv_token:-}")"
  validate_field "$device_id" device_id '^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$'
  validate_ipv4 "$device_ip" device_ip
  validate_field "$vlan" vlan '^[0-9]{1,4}$'
  [ "$vlan" -ge 1 ] && [ "$vlan" -le 4094 ] \
    || { echo "ERROR: vlan must be between 1 and 4094" >&2; exit 1; }
  validate_ipv4 "$svi_ip" svi_ip
  validate_ipv4 "$svi_mask" svi_mask
  validate_ipv4 "$guest_ip" guest_ip
  if [ -n "$tok" ]; then
    validate_field "$tok" csv_token '^[A-Fa-f0-9]{32}$'
  fi
  [ -n "$tok" ] || tok="$(mint_enrollment "$device_id")"
  validate_field "$tok" enrollment_token '^[A-Fa-f0-9]{32}$'

  f="$OUT/install-$device_id.sh"
  cat > "$f" <<EOF
#!/usr/bin/env bash
# IRIS installer for device $device_id  (GENERATED — re-run the generator to change)
set -euo pipefail
REPO="\$(cd "\$(dirname "\$0")/../.." && pwd)"
export DEVICE_IP=$(shell_literal "$device_ip") VLAN=$(shell_literal "$vlan") SVI_IP=$(shell_literal "$svi_ip") SVI_MASK=$(shell_literal "$svi_mask") GUEST_IP=$(shell_literal "$guest_ip") DEVICE_ID=$(shell_literal "$device_id")
export CATALOG_URL=$(shell_literal "$CATALOG_URL") CATALOG_TOKEN=$(shell_literal "$tok")
export STAGE_HOST=$(shell_literal "$STAGE_HOST")
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
