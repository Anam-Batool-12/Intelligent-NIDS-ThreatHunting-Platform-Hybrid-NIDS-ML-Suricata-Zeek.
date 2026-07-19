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
|---------|--------------------|----------|--------------|--------------------|
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
| Python detection modules | ✅ Done | 5 detectors implemented and tested: slow port scan, brute force, DoS, SQLi confirmation, DNS tunneling confirmation |
| ML anomaly detection | ⬜ Not started | `ml/*.py` |
| Threat intel enrichment | ⬜ Not started | `threat_intel/enrich.py` |
| FastAPI (alerts/timeline/stats) | ⬜ Skeleton only | `api/` |
| Custom dashboard (beyond Kibana) | ⬜ Not started | |
| Automatic scheduling (cron) | ⬜ Not started | detectors currently run manually |

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


### Useful commands
```bash
# Test config for syntax errors without starting the daemon
sudo suricata -T -c /etc/suricata/suricata.yaml -v

# Restart after config/rule changes
sudo systemctl restart suricata
sudo systemctl enable suricata  # ensure it survives reboot

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
sudo /opt/zeek/bin/zeekctl deploy    # re-apply config after changes
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

## Python Detection Modules (Completed)

### Purpose
Suricata's custom rules use short (5-60 second) threshold windows to stay
fast and memory-efficient. An attacker who spreads an attack out over
several minutes can stay under those thresholds indefinitely. The Python
detection modules close this gap by querying data already stored in
Elasticsearch over longer windows, and by cross-referencing repeated
Suricata alerts to separate one-off false positives from confirmed,
repeated attack behavior.

### Design
All five detectors share the same simple structure (deliberately written
with basic loops and dictionaries rather than Elasticsearch aggregation
queries, so the logic is easy to read and explain):
1. Query Elasticsearch for recent records (either Zeek's `nids-conn-*` or
   Suricata's `nids-alerts-*`, depending on the detector).
2. Loop through results, building a Python dictionary that counts
   occurrences per source IP (or per IP+port).
3. Compare each count against a threshold constant.
4. If crossed, print an alert and write a new document into a dedicated
   `nids-python-alerts` Elasticsearch index (kept separate from Suricata's
   own alerts so the source of each detection is always traceable).

### The five detectors

| Detector | Data source | Logic |
|---|---|---|
| `portscan_detector.py` | `nids-conn-*` (Zeek) | Counts distinct destination ports touched by each source IP over a 5-minute window; flags 15+ |
| `bruteforce_detector.py` | `nids-conn-*` (Zeek) | Counts connection attempts to login ports (22/SSH, 21/FTP, 3389/RDP) per source IP over 5 minutes; flags 10+ |
| `dos_detector.py` | `nids-conn-*` (Zeek) | Counts total connections per source IP over a 2-minute window (short, since DoS is fast); flags 100+ |
| `sqli_detector.py` | `nids-alerts-*` (Suricata) | Counts how many times each source IP triggered a Suricata SQLi rule over 10 minutes; flags 3+ as "confirmed" rather than a one-off false positive |
| `dns_tunnel_detector.py` | `nids-alerts-*` (Suricata) | Same confirmation pattern as SQLi, applied to Suricata's DNS tunneling rules |

**Why SQLi and DNS tunneling detectors read from Suricata's alerts rather
than raw traffic:** Zeek's `conn.log` (the only Zeek log currently ingested
into Elasticsearch) contains connection metadata only — no HTTP URIs or DNS
query strings. Extending the pipeline to ingest `http.log` and `dns.log`
would allow payload-level Python detection for these two attack types; for
now, these two detectors add value by turning Suricata's single alerts into
a confidence-scored "this happened repeatedly" signal, which is itself a
common real-world SOC technique for reducing alert fatigue.

### Environment
Detectors run inside a Python virtual environment (`venv/`) with the
`elasticsearch==8.14.0` client pinned to match the deployed Elasticsearch
server version (the latest client on PyPI, v9.x, is not guaranteed
compatible with an 8.x server).

### Verification
All five scripts were run manually against live data and completed without
errors ("Scan complete."). Full detection-accuracy evaluation (precision/
recall against labeled traffic) is planned once cron scheduling and the
benchmark dataset evaluation (Section 6.4 of the paper) are in place.

## Next Steps
1. Schedule the five Python detectors to run automatically via cron
   (e.g., every 2 minutes) instead of manual execution.
2. Train and integrate the ML anomaly detection model on Zeek connection
   features.
3. Build the FastAPI alert/timeline endpoints.
4. Build a custom dashboard/frontend beyond raw Kibana Discover views
   (or curate saved Kibana visualizations for the final deliverable).
5. (Optional) Extend the Logstash pipeline to ingest Zeek's `http.log` and
   `dns.log`, enabling payload-level Python detection for SQLi/DNS
   tunneling instead of the current Suricata-alert-correlation approach.
