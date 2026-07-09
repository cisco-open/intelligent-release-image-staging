# iris-fleet — CSV-driven per-device installers

One CSV with **network info only** → one self-contained installer per device.
All secrets (per-device catalog tokens, the rpc-secret, the catalog URL) are handled
automatically by the generator — it talks to the running server on this machine.

## Files
- `devices.csv` — one row per device: `device_id,device_ip,vlan,svi_ip,svi_mask,guest_ip`.
  SDA deployment (IS-IS underlay) assumed, so that's ALL you provide.
- `dist/` — generated: `install-<device_id>.sh` per device + `install-all.sh`. Gitignored
  (each generated file embeds that device's token).
- `iris-fleet.conf` — OPTIONAL overrides (`CATALOG_URL`, `STAGE_HOST`, …). Normally not needed.

## Workflow (run on the server machine)
1. Server running (`docker compose -f ../server/docker-compose.yml up -d --build`).
2. Edit `devices.csv` (copy from `devices.csv.example`).
3. `../tools/gen-device-installers.sh`
   - reads the rpc-secret from the container
   - gives every device its own token (created + registered automatically; the
     container is restarted only when new tokens were added)
   - derives the catalog/stage URLs from this machine's IP (`IRIS_HOST_IP` to override)
4. Run a device's package: `dist/install-100.92.9.x.sh` (add `--dry-run` to preview).

After a package runs, the device self-deploys: its 60-second EEM timer unpacks the
dropped bundle, starts the BitTorrent client (10-peer cap), and runs the agent —
which pulls the device's assigned image, verifies it, and stages it at flash root
via native EEM. **Staging only — never install/activate/reload.**
