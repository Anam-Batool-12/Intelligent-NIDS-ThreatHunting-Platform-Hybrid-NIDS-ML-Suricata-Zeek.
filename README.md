# Intelligent Network Intrusion Detection & Threat Hunting Platform

A hybrid network intrusion detection system combining signature-based detection
(Suricata + custom rules), protocol-level logging (Zeek + custom scripting),
an ELK-based log pipeline, custom Python attack detectors, and machine
learning anomaly detection - unified behind a REST API and Kibana dashboard.

## Why this project

Commercial SIEM/IDS platforms (Splunk, CrowdStrike) are expensive and out of
reach for students, independent researchers, and small organizations.
Open-source tools like Suricata and Zeek exist individually, but rarely get
wired into one working, documented pipeline. This project combines them:
Suricata for fast signature-based alerts, Zeek for detailed connection
context, custom Python detectors for attacks that fall below Suricata's
real-time thresholds, and an Isolation Forest model for anomalies no rule
was written for.

## Architecture
Network Traffic
|
v
[Suricata] --eve.json-->  [Logstash] --> [Elasticsearch] --> [Kibana Dashboard]
[Zeek]     --conn/dns/http logs-->  |            ^
|                              |            |
v                              v            |
[Python Detectors]  <-------->  [ML Anomaly Engine]
|                              |
+------------> [nids-python-alerts index] ----> [FastAPI] --> /alerts /timeline /stats 
## Features

- **Real-time traffic capture** via Suricata (af-packet) and Zeek
- **12 custom Suricata rules** covering DoS, Port Scan, Brute Force,
  SQL Injection, and DNS Tunneling
- **Custom Zeek script** implementing DNS tunneling heuristics via the
  SumStats framework (long query names, high query rate, high TXT volume)
- **5 custom Python detectors** that catch slow/low-rate attacks Suricata's
  short time-windows miss, by analyzing Zeek's stored connection data over
  longer windows
- **Machine learning anomaly detection** (Isolation Forest, scikit-learn)
  trained on live connection features (duration, bytes, packets)
- **ELK pipeline**: Logstash parses Suricata + Zeek logs into Elasticsearch;
  Kibana provides an interactive dashboard
- **FastAPI backend** exposing `/alerts`, `/timeline`, and `/stats` as JSON
- **Fully automated via cron** - detectors, ML predictor, and the ELK stack
  all run/restart without manual intervention

## Project Status

| Component | Status |
|---|---|
| Suricata (custom rules) | Done |
| Zeek (custom DNS script) | Done |
| Logstash to Elasticsearch pipeline | Done |
| Kibana Dashboard | Done |
| Python detection modules (5) | Done |
| ML anomaly detection | Done |
| Cron automation | Done |
| FastAPI backend | Done |
| Threat intel enrichment | Not started |
| CIC-IDS2017 benchmark evaluation | Not started |

## Tech Stack

Python - Suricata - Zeek - Elasticsearch - Logstash - Kibana - Docker -
scikit-learn - FastAPI

## Lab Setup

- **Sensor host:** Kali Linux (VMware), monitoring interface bridged to the
  physical network
- **Attacker host:** Debian (VirtualBox), bridged to the same network
  segment, used to generate real attack traffic (port scans, etc.) for
  testing
- Full setup notes and troubleshooting log: see
  [`docs/architecture.md`](docs/architecture.md)

## Quick Start

```bash
git clone <repo-url>
cd network-ids-platform
docker compose up -d elasticsearch logstash kibana
```

Suricata and Zeek run on the host directly (not in Docker, since they need
direct network interface access) - see `docs/architecture.md` for sensor
deployment steps.

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
uvicorn api.main:app --reload
```

Then visit `http://localhost:8000/docs` for the interactive API, or
`http://localhost:5601` for Kibana.

## Repository Structure
capture/suricata/rules/custom.rules   - 12 custom Suricata detection rules
capture/zeek/scripts/                 - custom DNS tunneling detection script
detection/                            - 5 Python detection modules
ml/                                   - Isolation Forest training + prediction
api/                                  - FastAPI backend
pipeline/logstash/                    - Logstash pipeline config
docker-compose.yml                    - Elasticsearch, Logstash, Kibana
docs/architecture.md                  - full technical writeup + issues fixed
## License

MIT - see [LICENSE](LICENSE).
