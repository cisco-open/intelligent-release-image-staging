<!--
Copyright 2026 Cisco Systems, Inc. and its affiliates

SPDX-License-Identifier: Apache-2.0
-->

# Automate with the API

## What this is for

Log in, assign an image to a device, and poll until it reports the image
staged. The routes and fields are in [Console API](../reference/console-api.md).

## In the Console

Do the same by hand with
[Assign images and check staging status](assignments.md). The Console lists
the routes at **Help → Local API reference (Swagger)**.

## With the API

Collect the Console address, the CA file your Console certificate chains to, an
admin username with its password in a file only you can read, and the device
and image ids from `GET /api/v1/devices` and `GET /api/v1/images`. Every route
needs the session cookie, and state-changing methods also need the
`X-CSRF-Token` header.

### 1. Log in

```bash
set -e
umask 077
CONSOLE=https://console.example
CA=/path/to/console-ca.pem
DEVICE='<device id>'
IMAGE='<image id>'

python3 -c 'import json, sys; print(json.dumps({"username": sys.argv[1], "password": open(sys.argv[2]).read().strip()}))' \
  '<username>' /path/to/admin-password |
  curl -fsS --cacert "$CA" -c session.cookie \
    -H 'Content-Type: application/json' \
    -X POST "$CONSOLE/api/v1/login" --data @- -o login.json

CSRF=$(python3 -c 'import json; print(json.load(open("login.json"))["csrf"])')
```

`login.json` holds the CSRF token; `session.cookie` holds the session.

!!! warning

    Keep `session.cookie` and `login.json` as private as the password file.

### 2. Assign the image

```bash
curl -fsS --cacert "$CA" -b session.cookie --get \
  --data-urlencode "q=$DEVICE" "$CONSOLE/api/v1/devices" -o devices.json
AFTER=$(python3 -c 'import json; print(json.load(open("devices.json"))["now"])')

python3 -c 'import json, sys; print(json.dumps({"image_ids": [sys.argv[1]]}))' "$IMAGE" |
  curl -fsS --cacert "$CA" -b session.cookie \
    -H "X-CSRF-Token: $CSRF" -H 'Content-Type: application/json' \
    -X POST "$CONSOLE/api/v1/devices/$DEVICE/assign" --data @-
```

The answer returns `assigned_image_ids`. Compare it with what you sent.
`AFTER` records the server clock before assignment; the next step requires a
newer heartbeat.

### 3. Poll until the device reports the image staged

```bash
deadline=$((SECONDS + 3600))
staged=0
while (( SECONDS < deadline )); do
  curl -fsS --cacert "$CA" -b session.cookie --get \
    --data-urlencode "q=$DEVICE" "$CONSOLE/api/v1/devices" -o devices.json
  if python3 - "$DEVICE" "$IMAGE" "$AFTER" <<'PY'
import json, sys
document = json.load(open("devices.json"))
device_id, image_id, after = sys.argv[1:]
row = next((r for r in document["devices"]
            if r["device_id"] == device_id), {})
seen = row.get("last_seen") or 0
fresh = seen > float(after) and 0 <= document["now"] - seen < 600
assigned = image_id in (row.get("assigned_image_ids") or [])
errored = image_id in (row.get("errored_image_ids") or [])
staged_ids = row.get("staged_image_ids")
ready = (image_id in staged_ids if staged_ids is not None else
         row.get("current_image_id") == image_id
         and row.get("stage_state") == "ready")
sys.exit(0 if fresh and assigned and ready and not errored else 1)
PY
  then
    staged=1
    break
  fi
  sleep 60
done
if (( ! staged )); then
  echo "Timed out: inspect the device's current status before retrying." >&2
fi
```

The loop waits up to one hour. It reads the current heartbeat, checks its age
against the server clock, and gives a current image error precedence over a
staged flag. Use the reports route to retain the transfer history as evidence.

### 4. Revoke the session

```bash
curl -fsS --cacert "$CA" -b session.cookie \
  -H "X-CSRF-Token: $CSRF" \
  -X POST "$CONSOLE/api/v1/logout"
test "$staged" -eq 1
```

The final check returns a failure exit status if the wait timed out.

## What you see

| Step | Route | A successful answer |
| --- | --- | --- |
| Log in | `POST /api/v1/login` | `{username, csrf}`, plus the session cookie |
| Assign | `POST /api/v1/devices/{device_id}/assign` | `{ok, assigned_image_ids, removed_image_ids}` |
| Poll | `GET /api/v1/devices?q=<device_id>` | `{devices: [...], now, ...}`; select the exact device id from the search results. Check `last_seen`, the current assignment and the heartbeat's staging fields. |
| Log out | `POST /api/v1/logout` | the session is revoked and the cookie expires |

## When a request is refused

Errors arrive as RFC 9457 Problem Details with
`Content-Type: application/problem+json`. Branch on `type` or `code`; they are
stable and listed in [API error codes](../problems.md).

```json
{
  "type": "https://cisco-open.github.io/intelligent-release-image-staging/docs/problems/#rate-limit-exceeded",
  "title": "Rate limit exceeded",
  "status": 429,
  "code": "rate-limit-exceeded"
}
```

| Status | What to do |
| --- | --- |
| 429, too many requests | The server can enforce one shared request budget across all Console users, sessions and hosts. Wait the `Retry-After` time, add jitter, then retry. Set the budget in [Server configuration](../reference/server-configuration.md). |
| 207, a partly applied change | `DELETE /api/v1/devices/<id>` answers 200 when cleanup was complete and 207 when part of it failed, with `degraded` naming the areas. Read the body, fix what it names, repeat only that work, and never retry a 207 the way you retry a 429. |

## Rules that catch scripts out

| Rule | What it means for your script |
| --- | --- |
| An assignment replaces the whole list | `{"image_ids": [...]}` replaces the ordered approved set, up to ten images, and an empty array unassigns all. Send `expect_image_ids` with the set you believe is stored: the server returns 409 with `assigned_image_ids` when it changed under you. |
| `Idempotency-Key` works only where a route advertises it | Onboard and undeploy accept one, assignment does not. It takes 8 to 128 safe characters and retains successful responses for up to 24 hours. The process-local cache holds 512 entries; eviction or a server restart can remove one sooner. Reusing a retained key with a different body is 409. After a lost response, read the catalog, deployment record and current device status before retrying. |
| Request acceptance does not prove staging | A 200 on the assignment route means the server stored the approved set. The device's reports are the only evidence that the image is on the flash and its hash checked. |

!!! warning

    A script that sends one image id to a device with two removes the other two.

## Related

- [Assign images and check staging status](assignments.md)
- [Monitor transfers and device reports](monitoring.md)
- [Console API](../reference/console-api.md)
- [API error codes](../problems.md)
