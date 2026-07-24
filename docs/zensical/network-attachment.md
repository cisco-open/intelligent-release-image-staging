# Network Attachment And VLAN Ownership

IRIS supports two explicit network attachment models for the staging agent.

## Routed - IRIS-managed app network

Routed attachment uses a dedicated IRIS VLAN and SVI. Deployment requires a
clean-device preflight and records the resources IRIS created in an applied
receipt. IRIS never silently adopts an existing VLAN or SVI.

## Inband - existing management VLAN

Inband attachment connects Guest Shell to an existing management VLAN. IRIS
does not create, configure, select, claim, or remove that VLAN, its SVI,
gateway, routes, or VRF. The operator must confirm the exact plan before the
onboarding action starts.

The initial implementation targets static IPv4 Guest Shell. It remains
fail-closed until physical preflight captures verify the target VLAN/SVI,
gateway reachability, and dedicated AppGig ownership on the supported IOS-XE
release. IOx, DHCP, VRF selection, and shared AppGig mutation are not
supported. If a receipt is missing, uncertain, or drifted, cleanup stops for
reconciliation instead of guessing at ownership.

Applied receipts live beneath `IRIS_STATE`, so the same lifecycle survives
Docker Compose state volumes and the Kubernetes PVC. They contain no passwords,
tokens, certificates, or raw device configuration.
