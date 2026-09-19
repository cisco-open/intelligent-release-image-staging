#!/bin/sh
# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

# Runs only inside the pinned Alpine verifier stages of server/Dockerfile.
# IRIS instruction keys are Ed25519. Use upstream OpenSSH's complete SSHSIG,
# allowed_signers and KRL implementation, without a crypto-library dependency.
set -eu
apk add --no-cache gcc=15.2.0-r5 musl-dev=1.2.6-r2 make=4.4.1-r4
mkdir /src /out
tar xzf /openssh.tar.gz -C /src --strip-components=1
cd /src
./configure --without-openssl --without-zlib --without-pam --without-libedit \
  --without-security-key-builtin --with-cflags=-Os --with-ldflags=-static
make -j2 ssh-keygen
strip ssh-keygen
# A static PIE is fine; a runtime loader or dynamic dependency is not.
if readelf -l ssh-keygen | grep -q INTERP \
   || readelf -d ssh-keygen | grep -q NEEDED; then
  echo 'ssh-keygen must be fully static' >&2
  exit 1
fi
./ssh-keygen -q -t ed25519 -N '' -f /tmp/test-key
printf 'verifier build check\n' > /tmp/message
./ssh-keygen -Y sign -f /tmp/test-key -n iris-instructions-v1 /tmp/message
printf 'iris-server %s\n' "$(cat /tmp/test-key.pub)" > /tmp/signers
./ssh-keygen -Y verify -f /tmp/signers -I iris-server -n iris-instructions-v1 \
  -s /tmp/message.sig < /tmp/message
cp ssh-keygen /out/ssh-keygen
cp LICENCE /out/ssh-keygen.LICENCE
