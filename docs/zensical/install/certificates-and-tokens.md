<!--
Copyright 2026 Cisco Systems, Inc. and its affiliates

SPDX-License-Identifier: Apache-2.0
-->

# Set up certificates and tokens

Skip this page until you replace the default identity.

## Before you start

- Sign in to the Console as the administrator. See [Sign in for the first time](first-sign-in.md).
- The certificate and key for the browser address, or a private authority's root certificate.

## Default browser identity

The default browser identity is generated and stored encrypted in `tls/console-fallback.pem.age`, and reused on restart. Separate Docker hosts and Kubernetes mount their own.

A browser warns about it the first time. Add it to each client's trust store after you check it through a channel you already trust, or install your own certificate. A certificate is tied to one address. Install a matching one whenever the address operators browse to changes.

To pass this certificate as `--cafile` to a tool such as `tools/api-exercise.py` while you still run the default identity, copy it out of the running server container, for example `docker compose exec iris cat /run/iris/tls/console-fallback.pem`, over a channel you already trust.

!!! warning
    Never disable TLS verification.

## Install your own Console certificate

1. Open **Settings → TLS & trust**.
2. Upload the certificate and its private key. Leaf-only or full chain both work.
3. Check the result. The Console reloads its listener.

## Install a root certificate authority

1. Open **Settings → TLS & trust**.
2. Paste or upload the certificate. It must be an X.509 certificate; one upload becomes one trust entry.
3. Confirm the entry appears in the list.

## Turn on the public bundle download

1. Open **Settings → TLS & trust**.
2. Set the download URL, starting with `https://`. Default: Cisco's Trusted Root Store, `https://www.cisco.com/security/pki/trs/ios.p7b`.
3. Turn on automatic download. The server checks every 24 hours.
4. Start a download and watch the job finish. Accepted: PEM, base64, a PKCS#7 bundle, and signed wrappers.

## Create the scrape token

Do this only if a Prometheus server or collector scrapes the metrics listener. Create the token on the server host and give the scraper the same value as its `credentials_file`:

```bash
umask 077
mkdir -p ~/.config/iris
openssl rand -hex 32 > ~/.config/iris/observability-token
export IRIS_OBSERVABILITY_TOKEN_FILE_HOST=$HOME/.config/iris/observability-token
sudo chown 10001 "$IRIS_OBSERVABILITY_TOKEN_FILE_HOST"
printf 'IRIS_OBSERVABILITY_TOKEN_FILE_HOST=%s\n' \
  "$IRIS_OBSERVABILITY_TOKEN_FILE_HOST" >> server/.env
```

Both containers run as user and group `10001`; the `chown` lets them read the file. Recreate the server container to pick up the mount; see [Send telemetry to Splunk](../user-guide/splunk.md). For rotation, see [Rotate credentials and certificates](../admin-guide/rotations.md).

## How the management credential is handled

The Console's management credential is compared against the current and previous values in constant time before route lookup or body buffering. It never appears in an environment value, URL, process argument, exception, or audit entry.

## Credential files on Kubernetes

The same material arrives as Secrets, created before you apply the manifests. [Install on Kubernetes](kubernetes.md) has the commands. Create both `current` files, and the two `previous` files empty.

| File | Secret | Format |
| --- | --- | --- |
| `current` and `previous` | `iris-tier-auth` | The management record |
| `current` and `previous` | `iris-observability-auth` | The raw token value |
| `headers` | `iris-otlp-headers` | Comma-separated `Name=Value` headers |
| `tls.crt` and `tls.key` | `iris-console-tls` | The browser certificate |
| `tls.crt` and `tls.key` | `iris-management-tls` | The management certificate, with service names as subject alternative names |

## Verify

- The Console settings view lists the certificate, the trust entries, and the download settings.
- The Console loads with no warning from a client that trusts your authority, and keeps that certificate after a restart. A scrape with the token succeeds; one without it is refused.

## Next steps

- [Build and publish the device packages](device-packages.md)
- [Verify the installation](verify.md)
- [Export telemetry](../user-guide/telemetry-export.md)
