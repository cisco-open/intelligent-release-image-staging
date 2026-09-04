#!/usr/bin/env bash

# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

# Container entrypoint for the IRIS coordination server. Decrypts pre-existing
# age ciphertext from the config volume to tmpfs (/run/iris) on every start;
# never persists plaintext. Then launches tracker + catalog + seeder and
# supervises them — if any exits, the container exits so the restart policy
# brings it back. Stdlib Python + the static aria2c; no systemd.
set -euo pipefail

# One-shot commands (e.g. `docker compose run --rm iris iris-bootstrap`) reach
# this fixed ENTRYPOINT as arguments ($@). Exec them in place of the normal
# tracker/catalog/seeder supervisor below — otherwise the arg is ignored and
# the decrypt loop fails closed on a still-empty config volume, which is
# exactly the fresh-volume bootstrap iris-bootstrap exists to resolve. Safe:
# the image sets no CMD and compose sets no command, so normal `up` reaches
# here with zero args and falls through. PATH includes /opt/iris/server, so a
# bare `iris-bootstrap` resolves.
if [ "$#" -gt 0 ]; then
  exec "$@"
fi

IRIS_STATE="${IRIS_STATE:-/var/lib/iris}"
IRIS_CONFIG="${IRIS_CONFIG:-/etc/iris}"
IRIS_LOG="${IRIS_LOG:-/var/log/iris}"
IRIS_RUN="${IRIS_RUN:-/run/iris}"
IRIS_AGE_BIN="${IRIS_AGE_BIN:-age}"
IRIS_AGE_KEY_FILE="${IRIS_AGE_KEY_FILE:-/run/secrets/iris_age_key}"
# TLS trust + console-cert override (console-managed; absent = today's behavior)
IRIS_TRUST_DIR="${IRIS_TRUST_DIR:-$IRIS_CONFIG/tls/trust}"
IRIS_CA_BUNDLE="${IRIS_CA_BUNDLE:-$IRIS_RUN/tls/ca-bundle.pem}"
IRIS_GUI_CERT="${IRIS_GUI_CERT:-$IRIS_RUN/tls/gui-cert.pem}"
IRIS_GUI_FALLBACK_CERT="${IRIS_GUI_FALLBACK_CERT:-$IRIS_RUN/tls/console-fallback.pem}"
IRIS_MANAGEMENT_API_CERT="${IRIS_MANAGEMENT_API_CERT:-$IRIS_RUN/tls/management-crt.pem}"
IRIS_MANAGEMENT_API_KEY="${IRIS_MANAGEMENT_API_KEY:-$IRIS_RUN/tls/key.pem}"
IRIS_CONSOLE_SETUP_TOKEN_FILE="${IRIS_CONSOLE_SETUP_TOKEN_FILE:-$IRIS_RUN/console-setup-token}"
mkdir -p "$IRIS_STATE/torrents" "$IRIS_CONFIG/tls" "$IRIS_TRUST_DIR" "$IRIS_LOG" \
  "$IRIS_RUN/tls"
# Keep the plaintext dir private. Running non-root (uid 10001), we may not OWN
# the mountpoint — compose mounts the tmpfs with uid=10001,mode=0700 (chmod
# succeeds and is a no-op), but Kubernetes' Memory emptyDir stays root-owned
# (fsGroup grants group access only) and chmod by a non-owner fails. The mount
# options / fsGroup are the enforcement there, so don't abort on it.
chmod 700 "$IRIS_RUN" 2>/dev/null || true

# Docker Compose file-backed Secrets may be exposed with engine-controlled
# permissions. Copy the first-run Console credential into this container's
# private tmpfs and validate the private copy in management_api.py. Kubernetes
# mounts a group-readable projected Secret directly and leaves SOURCE unset.
if [ -n "${IRIS_CONSOLE_SETUP_TOKEN_SOURCE:-}" ]; then
  if [ ! -f "$IRIS_CONSOLE_SETUP_TOKEN_SOURCE" ] || \
     [ ! -s "$IRIS_CONSOLE_SETUP_TOKEN_SOURCE" ]; then
    echo "FATAL: Console setup credential source is unavailable — refusing to start" >&2
    exit 1
  fi
  setup_tmp="${IRIS_CONSOLE_SETUP_TOKEN_FILE}.tmp"
  cp "$IRIS_CONSOLE_SETUP_TOKEN_SOURCE" "$setup_tmp"
  chmod 600 "$setup_tmp"
  mv -f "$setup_tmp" "$IRIS_CONSOLE_SETUP_TOKEN_FILE"
fi

# At-rest: the persistent volume holds ONLY ciphertext (*.age). The master
# age identity is supplied out-of-band (a Docker secret), never on the volume.
# Missing key => fail closed before any plaintext is written.
if [ ! -f "$IRIS_AGE_KEY_FILE" ]; then
  echo "FATAL: master key $IRIS_AGE_KEY_FILE not found — refusing to start (fail closed)" >&2
  exit 1
fi

# Decrypt the three secret files from the volume into tmpfs (/run/iris).
# decrypt_to fails closed: a bad/invalid key raises and nothing plaintext
# lands on the volume.
script_dir="$(cd "$(dirname "$0")" && pwd)"
for pair in \
  "$IRIS_CONFIG/secrets.json.age:$IRIS_RUN/secrets.json" \
  "$IRIS_CONFIG/rpc-secret.age:$IRIS_RUN/rpc-secret" \
  "$IRIS_CONFIG/tls/key.pem.age:$IRIS_RUN/tls/key.pem"; do
  enc="${pair%%:*}"; out="${pair##*:}"
  if [ ! -f "$enc" ]; then
    echo "FATAL: encrypted file $enc missing — refusing to start (fail closed)" >&2
    exit 1
  fi
  IRIS_AGE_BIN="$IRIS_AGE_BIN" PYTHONPATH="$script_dir" python3 - "$enc" "$out" "$IRIS_AGE_KEY_FILE" <<'PY' || {
import os, sys
import secretfs
secretfs.decrypt_to(sys.argv[1], sys.argv[2], sys.argv[3],
                    age_bin=os.environ["IRIS_AGE_BIN"])
PY
    echo "FATAL: could not decrypt $enc — bad master key? (fail closed)" >&2
    exit 1
  }
done

# Build the plaintext combined cert (cert+key) in tmpfs for ssl.load_cert_chain.
cat "$IRIS_CONFIG/tls/crt.pem" "$IRIS_RUN/tls/key.pem" > "$IRIS_RUN/tls/cert.pem"
chmod 600 "$IRIS_RUN/tls/cert.pem"

# Compose can derive a separate internal identity from the already-decrypted
# key without changing the device-pinned catalog certificate. Kubernetes
# mounts a dedicated management TLS Secret and leaves this switch disabled.
# The exported CA contains public certificate material only and is the one
# narrow shared bootstrap file the state-free console needs before HTTPS can
# carry its tier credential.
if [ "${IRIS_MANAGEMENT_API_GENERATE_CERT:-0}" = "1" ]; then
  mgmt_tmp="$IRIS_RUN/tls/.management-crt.pem.tmp"
  openssl req -x509 -new -key "$IRIS_MANAGEMENT_API_KEY" -days 3650 \
    -subj "/CN=iris" \
    -addext "subjectAltName=DNS:iris,DNS:iris-server,DNS:localhost,IP:127.0.0.1,IP:${IRIS_HOST_IP}" \
    -out "$mgmt_tmp" >/dev/null 2>&1
  chmod 600 "$mgmt_tmp"
  mv -f "$mgmt_tmp" "$IRIS_MANAGEMENT_API_CERT"
fi
if [ ! -s "$IRIS_MANAGEMENT_API_CERT" ] || [ ! -s "$IRIS_MANAGEMENT_API_KEY" ]; then
  echo "FATAL: management API TLS identity unavailable — refusing to start" >&2
  exit 1
fi
if [ -n "${IRIS_MANAGEMENT_API_CA_EXPORT:-}" ]; then
  mkdir -p "$(dirname "$IRIS_MANAGEMENT_API_CA_EXPORT")"
  ca_tmp="${IRIS_MANAGEMENT_API_CA_EXPORT}.tmp"
  cp "$IRIS_MANAGEMENT_API_CERT" "$ca_tmp"
  chmod 644 "$ca_tmp"
  mv -f "$ca_tmp" "$IRIS_MANAGEMENT_API_CA_EXPORT"
fi

# Compose bootstrap for an independent browser-facing identity. This key is
# never the device-pinned catalog key. It crosses only the authenticated,
# CA-verified management hop into the console's tmpfs. Kubernetes instead
# mounts its operator-issued console identity and leaves generation disabled.
if [ "${IRIS_GUI_FALLBACK_GENERATE:-0}" = "1" ]; then
  fallback_key="$IRIS_RUN/tls/.console-fallback-key.pem"
  fallback_crt="$IRIS_RUN/tls/.console-fallback-crt.pem"
  openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
    -subj "/CN=${IRIS_HOST_IP}" \
    -addext "subjectAltName=IP:${IRIS_HOST_IP}" \
    -keyout "$fallback_key" -out "$fallback_crt" >/dev/null 2>&1
  cat "$fallback_crt" "$fallback_key" > "${IRIS_GUI_FALLBACK_CERT}.tmp"
  chmod 600 "${IRIS_GUI_FALLBACK_CERT}.tmp"
  mv -f "${IRIS_GUI_FALLBACK_CERT}.tmp" "$IRIS_GUI_FALLBACK_CERT"
  rm -f "$fallback_key" "$fallback_crt"
fi

# Local Compose bootstrap for the narrowly scoped tier credential. The named
# volume contains only current/previous management tokens; Kubernetes supplies
# the same files from a Secret. Values never enter env, argv, or logs.
if [ "${IRIS_MANAGEMENT_API_GENERATE_TOKEN:-0}" = "1" ] && \
   [ ! -s "${IRIS_MANAGEMENT_API_TOKEN_FILE:-}" ]; then
  PYTHONPATH="$script_dir" python3 - "${IRIS_MANAGEMENT_API_TOKEN_FILE}" <<'PY'
import json
import os
import secrets
import sys
import tempfile

path = sys.argv[1]
directory = os.path.dirname(path) or "."
os.makedirs(directory, exist_ok=True)
fd, tmp = tempfile.mkstemp(dir=directory, prefix=".management-token-")
try:
    with os.fdopen(fd, "w") as stream:
        json.dump({"scope": "management", "token": secrets.token_urlsafe(48)}, stream)
        stream.write("\n")
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)
finally:
    try:
        os.remove(tmp)
    except FileNotFoundError:
        pass
PY
fi

# Optional console-only cert override: when the operator installed a custom
# console certificate from Settings (durable gui-crt.pem + age-encrypted
# gui-key.pem.age), build the combined $IRIS_GUI_CERT in tmpfs the same way.
# UNLIKE the identity cert above this is best-effort: a corrupt or
# undecryptable override must NOT stop the container — gui_server falls back
# to the bootstrap cert (IRIS_CERT), so a bad uploaded cert can never lock
# the operator out. On failure any stale runtime override is removed so the
# fallback actually engages.
if [ -f "$IRIS_CONFIG/tls/gui-crt.pem" ] && [ -f "$IRIS_CONFIG/tls/gui-key.pem.age" ]; then
  if IRIS_AGE_BIN="$IRIS_AGE_BIN" PYTHONPATH="$script_dir" python3 - \
      "$IRIS_CONFIG/tls/gui-key.pem.age" "$IRIS_RUN/tls/gui-key.pem" "$IRIS_AGE_KEY_FILE" <<'PY'
import os, sys
import secretfs
secretfs.decrypt_to(sys.argv[1], sys.argv[2], sys.argv[3],
                    age_bin=os.environ["IRIS_AGE_BIN"])
PY
  then
    # gui_tls.persist_override writes the durable pair key-first, then cert
    # (secretfs.encrypt_from, then the crt write) — a crash between the two
    # can leave a NEW key paired with a STALE cert on the volume. Compare
    # public keys (not modulus: future-proof beyond the RSA iris-bootstrap
    # mints today) before ever combining them into a servable file, so a
    # mismatched pair warns and falls back instead of crashing later inside
    # ssl.load_cert_chain.
    gui_cert_pub="$(openssl x509 -in "$IRIS_CONFIG/tls/gui-crt.pem" -noout -pubkey 2>/dev/null)" || gui_cert_pub=""
    gui_key_pub="$(openssl pkey -in "$IRIS_RUN/tls/gui-key.pem" -pubout 2>/dev/null)" || gui_key_pub=""
    if [ -n "$gui_cert_pub" ] && [ "$gui_cert_pub" = "$gui_key_pub" ]; then
      cat "$IRIS_CONFIG/tls/gui-crt.pem" "$IRIS_RUN/tls/gui-key.pem" > "$IRIS_GUI_CERT"
      chmod 600 "$IRIS_GUI_CERT"
    else
      echo "WARNING: gui-crt.pem and gui-key.pem.age do not form a matching certificate/key pair — console keeps the built-in certificate" >&2
      rm -f "$IRIS_RUN/tls/gui-key.pem" "$IRIS_GUI_CERT"
    fi
  else
    echo "WARNING: could not decrypt tls/gui-key.pem.age — console keeps the built-in certificate" >&2
    rm -f "$IRIS_RUN/tls/gui-key.pem" "$IRIS_GUI_CERT"
  fi
else
  # Durable override pair absent (never uploaded, or removed via Settings).
  # Runtime files are derived state on the Compose tmpfs or Kubernetes memory
  # emptyDir; when the durable pair is absent, sweep any stale override rather
  # than serving it, just as an empty trust dir sweeps a stale CA bundle below.
  rm -f "$IRIS_RUN/tls/gui-key.pem" "$IRIS_GUI_CERT"
fi

# Build the outbound-TLS trust bundle from the durable trust dir (installed
# root CAs + the optional downloaded public bundle). Deterministic
# lexicographic concat — must match server/trust.py rebuild_bundle(). An
# empty trust dir means no bundle: outbound consumers then verify against
# the default system store only.
shopt -s nullglob
trust_srcs=("$IRIS_TRUST_DIR"/*.pem)
shopt -u nullglob
if [ "${#trust_srcs[@]}" -gt 0 ]; then
  # Per-file, not one `cat "${trust_srcs[@]}"`: a single unreadable entry
  # (e.g. a directory named *.pem) would otherwise abort the WHOLE container
  # start under set -e. Mirrors trust.py rebuild_bundle(), which skips a bad
  # entry (except OSError: continue) rather than failing the whole rebuild.
  : > "$IRIS_CA_BUNDLE"
  bundle_wrote=0
  for f in "${trust_srcs[@]}"; do
    if cat "$f" >> "$IRIS_CA_BUNDLE" 2>/dev/null; then
      bundle_wrote=1
    else
      echo "WARNING: skipping unreadable trust entry $f" >&2
    fi
  done
  if [ "$bundle_wrote" -eq 1 ]; then
    chmod 600 "$IRIS_CA_BUNDLE"
  else
    # every entry was bad — same as an empty trust dir
    rm -f "$IRIS_CA_BUNDLE"
  fi
else
  rm -f "$IRIS_CA_BUNDLE"
fi

export IRIS_STATE IRIS_CONFIG IRIS_RUN
export IRIS_SECRETS="$IRIS_RUN/secrets.json"
export IRIS_RPC_SECRET_FILE="$IRIS_RUN/rpc-secret"
export IRIS_CERT="$IRIS_RUN/tls/cert.pem"
export IRIS_TELEMETRY_CERT="${IRIS_TELEMETRY_CERT:-$IRIS_CERT}"
export IRIS_TELEMETRY_CA="${IRIS_TELEMETRY_CA:-$IRIS_CONFIG/tls/crt.pem}"
export IRIS_AUDIT="${IRIS_AUDIT:-$IRIS_CONFIG/audit.jsonl}"
export IRIS_SECRETS_ENC="${IRIS_SECRETS_ENC:-$IRIS_CONFIG/secrets.json.age}"
export IRIS_AGE_BIN IRIS_AGE_KEY_FILE
export IRIS_GUI_CERT IRIS_GUI_FALLBACK_CERT IRIS_TRUST_DIR IRIS_CA_BUNDLE
export IRIS_MANAGEMENT_API_CERT IRIS_MANAGEMENT_API_KEY
export IRIS_CONSOLE_SETUP_TOKEN_FILE

# Compose represents an omitted optional bind with /dev/null.  Never pass that
# character device to strict credential-file validation as an alleged previous
# token, and never treat it as an OTLP header file. A real mounted regular file
# remains configured unchanged (including Kubernetes projected Secret files).
if [ -n "${IRIS_OBSERVABILITY_PREVIOUS_TOKEN_FILE:-}" ] && \
   [ ! -f "$IRIS_OBSERVABILITY_PREVIOUS_TOKEN_FILE" ]; then
  export IRIS_OBSERVABILITY_PREVIOUS_TOKEN_FILE=""
fi
if [ -n "${IRIS_OTLP_HEADERS_FILE:-}" ] && \
   [ ! -f "$IRIS_OTLP_HEADERS_FILE" ]; then
  export IRIS_OTLP_HEADERS_FILE=""
fi

# Writable volume for images uploaded via the GUI console; the seeder's
# restart-reseed walk (seed-launch.sh) also covers this dir so uploads
# survive a container restart.
export IRIS_IMAGES_DIR="${IRIS_IMAGES_DIR:-/var/lib/iris-images}"
mkdir -p "$IRIS_IMAGES_DIR"

# Served bootstrap/package artifacts may live anywhere on a container volume.
# Compose uses /srv/artifacts; Kubernetes uses a directory on its data PVC.
export IRIS_ARTIFACTS_DIR="${IRIS_ARTIFACTS_DIR:-/srv/artifacts}"
mkdir -p "$IRIS_ARTIFACTS_DIR/staging" 2>/dev/null || true

# Self-provision the derivable served artifacts (Guest Shell bundle,
# bootstrap.sh, iris-catalog.pem) into the artifacts dir so a fresh deploy
# doesn't fail onboarding on missing files. Best-effort (never blocks startup).
# Both IOx tars and iris-xr.rpm still have to be built out of band.
bash /opt/iris/server/provision-served.sh "$IRIS_ARTIFACTS_DIR" || true

if [ "${SKIP_SUPERVISE:-0}" = "1" ]; then
  echo "iris entrypoint: secrets decrypted to $IRIS_RUN (SKIP_SUPERVISE=1, not launching services)"
  exit 0
fi

cd /opt/iris/server
PIDS=()

stop_services() {
  if [ "${#PIDS[@]}" -gt 0 ]; then
    kill "${PIDS[@]}" 2>/dev/null || true
    wait "${PIDS[@]}" 2>/dev/null || true
  fi
}

on_shutdown() {
  trap - TERM INT
  echo "iris container stopping"
  stop_services
  exit 0
}

trap on_shutdown TERM INT

python3 tracker.py & T=$!
python3 catalog.py & C=$!
RPC_PORT="${RPC_PORT:-6800}" IRIS_ROOT=/opt/iris IRIS_LOG="$IRIS_LOG" \
  IMAGES_DIR="${IMAGES_DIR:-/opt/images/iosxe/c9300}" \
  IRIS_IMAGES_DIR="$IRIS_IMAGES_DIR" \
  SEEDER_LOG=- \
  ARIA2=/opt/iris/bin/aria2c bash seed-launch.sh & S=$!
# Artifact server (HTTPS): explicit API consumers authenticate with resource-
# bound device Basic credentials before path translation/existence. Unchanged
# Guest Shell onboarding still pulls the explicit static files and time-bounded
# high-entropy staging capabilities with IOS `copy https:`.
# Log to the container log like the other services — discarding stdout/stderr
# here hides artifact-server startup/serving failures for authenticated API
# consumers, so silent failures still matter.
python3 artifact_server.py & A=$!

# Stateful management API (internal HTTPS :9443). The separate console BFF is
# its only network consumer; browser session and CSRF checks remain here beside
# the encrypted state they protect.
python3 management_api.py & M=$!
PIDS=("$T" "$C" "$S" "$A" "$M")

echo "iris container up: tracker :6969  catalog :8443 (https)  artifacts :8000 (https)  management :9443 (https, internal)  seeder rpc :6800"
wait -n "$T" "$C" "$S" "$A" "$M" || true
echo "an iris service exited — stopping container" >&2
stop_services
exit 1
