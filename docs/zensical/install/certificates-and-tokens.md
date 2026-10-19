<!--
Copyright 2026 Cisco Systems, Inc. and its affiliates

SPDX-License-Identifier: Apache-2.0
-->

# Trust the Console certificate and configure credentials

Setup creates the initial certificates and service credentials. Trust the
Console's public certificate before signing in, then use Settings for optional
certificate changes and monitoring.

## Before you start

- Have a running IRIS deployment and know its Console address.
- For a managed installation, know its state directory.
- For Settings changes, [sign in as the administrator](first-sign-in.md).

## Default browser identity

The default browser identity is generated and stored encrypted in
`tls/console-fallback.pem.age`, and reused on restart. Separate Docker hosts and
Kubernetes mount their own browser identity.

For a manually provisioned deployment, follow the
[public certificate export procedure](../reference/manual-installation/certificates-and-tokens.md#default-browser-identity).

For a managed installation, setup exports the public Console certificate to `requests/console-cert.pem`
inside the installation's state directory. Obtain it through your authenticated
host connection. For an installation using `/var/lib/iris-installer/my-iris`:

```bash
sudo cat /var/lib/iris-installer/my-iris/requests/console-cert.pem > console-ca.pem
openssl x509 -in console-ca.pem -noout -sha256 -fingerprint
```

Compare that fingerprint with the certificate your browser receives, then add
`console-ca.pem` to your client's trust store. The certificate must cover every DNS name or IP address operators use. If that address changes, replace the certificate unless
it already covers the new address.

!!! warning
    Never disable TLS verification or copy the combined runtime PEM: it also
    contains the private key.

## Install your own Console certificate

1. Open **Settings → TLS & trust**.
2. Upload the certificate and its private key. Leaf-only or full chain both work.
3. Check the result. If the certificate was saved but reload was not confirmed,
   restart that Console. With several Console instances, restart the others too.
4. Open a new trusted connection to each Console and verify its served certificate.

Uploading a certificate changes the saved override, but reload reaches only the
Console that handled the request. A saved result alone does not prove a listener
is using the replacement.

## Install a root certificate authority

1. Open **Settings → TLS & trust**.
2. Paste or upload the certificate. It must be an X.509 certificate; one upload becomes one trust entry.
3. Confirm the entry appears in the list.

## Turn on the public bundle download

1. Open **Settings → TLS & trust**.
2. Set the download URL, starting with `https://`. Default: Cisco's Trusted Root Store, `https://www.cisco.com/security/pki/trs/ios.p7b`.
3. Turn on automatic download. The server checks every 24 hours.
4. Start a download and watch the job finish. Accepted: PEM, base64, a PKCS#7 bundle, and signed wrappers.

## Configure monitoring credentials

Choose `--observability` during setup to enable the authenticated metrics
listener. Set its scraper token through
[Rotate telemetry credentials](../admin-guide/console-credentials.md#replace-the-metrics-scraping-token).
Give the scraper the same token in its protected credentials file.

Setup provisions the Console-to-server credential and, on Kubernetes, the
required Secrets. Manage later changes through
[Rotate credentials and certificates](../admin-guide/rotations.md).
Manual credential-file layouts are in the
[certificate and token reference](../reference/manual-installation/certificates-and-tokens.md).

## Verify

- The Console lists the intended certificate and trust entries.
- A client that trusts the certificate opens the Console without a warning.
- A configured metrics scraper succeeds with its token; a request without one is refused.

## Next steps

- [Sign in for the first time](first-sign-in.md)
- [Verify the installation](verify.md)
- [Export telemetry](../user-guide/telemetry-export.md)
