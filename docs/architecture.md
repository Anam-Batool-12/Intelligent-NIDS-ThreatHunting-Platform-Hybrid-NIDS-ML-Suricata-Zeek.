# Architecture

## Overview

This platform combines signature-based detection (Suricata), protocol-level
logging (Zeek), an ELK log pipeline, custom Python attack detectors, and a
planned ML anomaly detection layer into a single correlated alerting system.

```
Network Traffic
     |
     v
[Suricata] --eve.json-->  [Logstash] --> [Elasticsearch] --> [Kibana Dashboard]
[Zeek]     --conn/dns/http logs-->  |            ^
     |                              |            |
     v                              v            |
[Python Detectors]  <-------->  [ML Anomaly Engine]
     |                              |
     +------------> [Alert Correlation Layer] ----> [FastAPI] --> Dashboard/Alerts/Timeline
```

## Lab Topology

| Host    | Hypervisor        | Role     | Network Mode | IP (example)      |
|---------|-------------------|----------|---------------|--------------------|
| Kali    | VMware Workstation | Sensor   | Bridged (`eth0`) | `192.168.100.x` |
| Debian  | VirtualBox         | Attacker | Bridged      | `192.168.100.x`   |

Both VMs are bridged to the physical WiFi network so traffic between them
traverses each host's monitored network interface — this is required for
Suricata/Zeek to actually observe the traffic. Same-host traffic (e.g., a
tool scanning `127.0.0.1` or its own primary IP) is routed via the kernel's
loopback shortcut and never reaches the af-packet capture point, so it will
not generate detections.

**Note on VMware + WiFi bridging:** by default VMware's bridged network
(`VMnet0`) is set to "Automatic," which can select the wrong or a
disconnected host adapter. If a bridged VM gets a `169.254.x.x`
(link-local/APIPA) address instead of a real DHCP lease, open
**Edit → Virtual Network Editor → VMnet0 → Bridged to**, and manually select
the active WiFi adapter (or use "Automatic Settings" and only enable the
WiFi adapter).

## Component Status

| Component | Status | Notes |
|---|---|---|
| Suricata (signature detection) | ✅ Done | Custom ruleset loaded, live scan detection verified |
| Zeek (protocol logging) | ✅ Done | Deployed via zeekctl, custom DNS tunneling script active, scan detection verified in `conn.log` |
| Logstash → Elasticsearch pipeline | ✅ Done | Both Suricata `eve.json` and Zeek `conn.log` flowing into Elasticsearch |
| Kibana Dashboard | ✅ Done | Data views created (`nids-alerts`, `nids-conn`), verified searchable (51K+ alert docs, 270 custom-rule alerts) |
| Python detection modules | ⬜ Skeleton only | `detection/*.py` — not yet implemented |
| ML anomaly detection | ⬜ Not started | `ml/*.py` |
| Threat intel enrichment | ⬜ Not started | `threat_intel/enrich.py` |
| FastAPI (alerts/timeline/stats) | ⬜ Skeleton only | `api/` |
| Custom dashboard (beyond Kibana) | ⬜ Not started | |

## Suricata Setup (Completed)

### Configuration
- **Interface:** `eth0` (af-packet capture)
- **HOME_NET:** `192.168.0.0/16,10.0.0.0/8,172.16.0.0/12`
- **Rule path:** `/var/lib/suricata/rules/` (this is the `default-rule-path`
  resolved from `suricata.yaml` on this install — confirm with
  `grep default-rule-path /etc/suricata/suricata.yaml`, as it can vary by
  distro/package)
- **Custom rules file:** added as an entry under `rule-files:` in
  `suricata.yaml`, alongside the Emerging Threats `suricata.rules`

### Custom Ruleset
12 rules, SID range `9000001`–`9000041`, covering DoS/flood, port scan,
brute force, SQL injection, and DNS tunneling. Full source:
[`capture/suricata/rules/custom.rules`](../capture/suricata/rules/custom.rules).

### Verification
A live TCP SYN scan from a second VM on the same network segment was used
to confirm the rules load and fire correctly (see
[research_paper.md § 6.1](research_paper.md#61-live-attack-simulation--port-scan-detection)
for the log excerpt and screenshots).

### Useful commands
```bash
# Test config for syntax errors without starting the daemon
sudo suricata -T -c /etc/suricata/suricata.yaml -v

# Restart after config/rule changes
sudo systemctl restart suricata
sudo systemctl enable suricata   # ensure it survives reboot

# Watch alerts live
sudo tail -f /var/log/suricata/fast.log

# Check interface capture stats
sudo suricatasc -c "iface-stat eth0"
```

## Zeek Setup (Completed)

### Installation
Kali's default `zeek` package (5.1.1) had broken dependencies against the
system's current `libc6`. Installed instead from the official Zeek OBS
repository (`security:zeek` Debian_Testing channel), which provided a
compatible build (8.2.1).

### Configuration
- Managed via `zeekctl` (install → deploy workflow) rather than running
  `zeek` directly, so it persists as a standalone service.
- `local.zeek` extended with `@load ./scripts/dns_tunnel_detect.zeek` to
  load the project's custom DNS tunneling heuristics, and with Community ID
  logging enabled for later Suricata/Zeek alert correlation.
- **Auto-start on boot:** zeekctl does not register a systemd service by
  default; a cron `@reboot` entry (`sleep 30 && zeekctl deploy`) was added
  to ensure Zeek restarts after VM reboot, once the network interface is
  ready.

### Verification
A live TCP SYN scan produced a clear signature in `conn.log`: many
connections from the same source port to sequential destination ports, all
with `REJ` (rejected/closed port) connection state — confirming Zeek
captures the same attack Suricata alerts on, independently, at the
connection-log level (useful both for ML feature extraction later, and for
correlating with Suricata alerts via Community ID).

### Useful commands
```bash
sudo /opt/zeek/bin/zeekctl status
sudo /opt/zeek/bin/zeekctl deploy     # re-apply config after changes
sudo tail -f /opt/zeek/logs/current/conn.log
```

## ELK Stack Setup (Completed)

### Deployment
Elasticsearch, Logstash, and Kibana (all v8.14.0) are run via Docker
Compose. Logstash mounts the live Suricata and Zeek log directories
read-only and ships parsed events into two daily-rotated Elasticsearch
indices: `nids-alerts-*` (from Suricata `eve.json`) and `nids-conn-*`
(from Zeek `conn.log`).

### Issues encountered and fixes
1. **Wrong Docker socket (Podman conflict):** the `podman-docker` package
   sets `DOCKER_HOST` to Podman's socket by default, causing
   `docker compose` to fail with a misleading "no such file or directory"
   error. Fixed with `unset DOCKER_HOST` (added to `.bashrc`, though note
   this must be re-verified per shell/session).
2. **Permission denied on Docker socket:** the user was not in the
   `docker` group. Fixed with `sudo usermod -aG docker $USER`.
3. **Wrong volume mount paths:** the initial `docker-compose.yml` mounted
   the project's local `capture/suricata` and `capture/zeek` config
   folders (which only contain configuration, not live logs) instead of
   the actual runtime log paths (`/var/log/suricata`,
   `/opt/zeek/logs/current`). Editing config files in place can silently
   leave duplicate/stale volume entries — always re-`grep` the compose file
   after edits and use `docker inspect <container> | grep -A3 Source` to
   confirm what's actually mounted, since `docker compose restart` does
   **not** pick up new volume definitions — `docker compose up -d
   --force-recreate <service>` is required.
4. **Zeek spool directory permissions:** `/opt/zeek/spool` was
   `drwxrws---` (no access for "others"), blocking the Logstash container's
   user from reading `conn.log` through the `current` symlink. Fixed with
   `chmod o+rx /opt/zeek/spool` (note: `chmod -R` on `/opt/zeek/logs`
   alone does not fix this, since `current` is a symlink to a different
   path entirely — use `namei -l <path>` to find exactly which directory
   in the chain is blocking access).

### Verification
Kibana Discover, querying the `nids-alerts` data view, showed 51,231 total
documents and 270 matching `alert.signature: "CUSTOM*"` (i.e., generated
by this project's own rules specifically, not the Emerging Threats
ruleset) — confirming the full pipeline from packet capture through to a
searchable dashboard.

### Useful commands
```bash
docker compose up -d elasticsearch logstash kibana
docker compose ps
docker compose logs logstash --tail 60
curl -s "http://localhost:9200/_cat/indices?v" | grep nids
```

## Next Steps
1. Implement Python detection modules that read from Elasticsearch and
   apply logic Suricata's static rules can't (e.g., slow/low-rate scans).
2. Train and integrate the ML anomaly detection model on Zeek connection
   features.
3. Build the FastAPI alert/timeline endpoints.
4. Build a custom dashboard/frontend beyond raw Kibana Discover views
   (or curate saved Kibana visualizations for the final deliverable).
