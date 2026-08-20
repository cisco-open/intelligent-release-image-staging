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
mkdir -p "$IRIS_STATE/torrents" "$IRIS_CONFIG/tls" "$IRIS_TRUST_DIR" "$IRIS_LOG" \
  "$IRIS_RUN/tls"
# Keep the plaintext dir private. Running non-root (uid 10001), we may not OWN
# the mountpoint — compose mounts the tmpfs with uid=10001,mode=0700 (chmod
# succeeds and is a no-op), but Kubernetes' Memory emptyDir stays root-owned
# (fsGroup grants group access only) and chmod by a non-owner fails. The mount
# options / fsGroup are the enforcement there, so don't abort on it.
chmod 700 "$IRIS_RUN" 2>/dev/null || true

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
export IRIS_AUDIT="${IRIS_AUDIT:-$IRIS_CONFIG/audit.jsonl}"
export IRIS_SECRETS_ENC="${IRIS_SECRETS_ENC:-$IRIS_CONFIG/secrets.json.age}"
export IRIS_AGE_BIN IRIS_AGE_KEY_FILE
export IRIS_GUI_CERT IRIS_TRUST_DIR IRIS_CA_BUNDLE

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
# doesn't fail onboarding on missing files. Best-effort (never blocks startup);
# only iris-arm64.tar (the aarch64 IOx package) still has to be built out-of-band.
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
# artifact server (HTTPS): devices `copy https://<host>:8000/...` the agent bundle
# + per-device configs from the configured artifacts volume. Serves over TLS with
# the SAME combined cert (IRIS_CERT) the catalog uses; the device trusts it via
# the per-device PKI trustpoint the installer pushes first. No auth here — the
# trustpoint gives confidentiality + server-auth and the payload IS the
# credential bundle (transport-security only; nothing installed/activated/reloaded).
# staging/ holds the ephemeral per-device configs gui_onboard.py
# (IRIS_STAGE_LOCAL=1) writes when the console is co-located with this artifact
# server; artifact_server.py sweeps them after STAGING_MAX_AGE_SECONDS.
# Log to the container log like the other services — discarding stdout/stderr
# here hides artifact-server startup/serving failures (the device fetches its
# agent bundle + per-device conf from this port, so silent failures matter).
python3 artifact_server.py & A=$!

# web console (HTTPS :8080): single-admin GUI to run IRIS end-to-end. Serves
# with the SAME combined cert (IRIS_CERT) as the catalog. Persists the admin
# credential + credential profiles into the age-encrypted store (IRIS_SECRETS_ENC),
# re-encrypting via IRIS_AGE_RECIPIENTS on write.
python3 gui_server.py & G=$!
PIDS=("$T" "$C" "$S" "$A" "$G")

echo "iris container up: tracker :6969  catalog :8443 (https)  artifacts :8000 (https)  console :8080 (https)  seeder rpc :6800"
wait -n "$T" "$C" "$S" "$A" "$G" || true
echo "an iris service exited — stopping container" >&2
stop_services
exit 1
