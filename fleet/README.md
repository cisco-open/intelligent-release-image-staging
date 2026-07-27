# iris-fleet — CSV-driven per-device installers

One CSV with **network info only** → one self-contained installer per device.
All secrets (per-device catalog tokens, the rpc-secret, the catalog URL) are handled
automatically by the generator — it talks to the running server on this machine.

## Files
- `devices.csv` — attachment-aware inventory (CSV v2). Each row declares a
  `management_type` (`routed` or `inband`) plus its addressing:
  `device_id,device_ip,management_type,iris_vlan,svi_ip,svi_mask,app_ip,app_mask,app_gateway,inband_vlan,ios_ssh_host,model,platform`.
  **routed** uses `iris_vlan`/`svi_*` (IRIS creates the VLAN/SVI); **inband**
  uses `inband_vlan`/`app_*` and attaches to an existing operator-owned VLAN
  that IRIS never changes. Attachment-aware onboarding runs through the
  Console/API (it records a receipt and runs preflight). The generator below is
  **routed-only** and refuses a v2 header — it is for legacy positional
  `device_id,device_ip,vlan,svi_ip,svi_mask,guest_ip` CSVs.
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
