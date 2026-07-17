# Automatic Scheduling (Cron)

All 5 Python detectors and the ML predictor run automatically via cron,
instead of manual execution. Docker (Elasticsearch/Logstash/Kibana) is
also started automatically on boot.

## Crontab entries
@reboot sleep 45 && cd /home/kali/network-ids-platform && /usr/bin/docker compose up -d elasticsearch logstash kibana
*/2 * * * * cd /home/kali/network-ids-platform && venv/bin/python3 detection/portscan_detector.py >> logs/portscan.log 2>&1
*/2 * * * * cd /home/kali/network-ids-platform && venv/bin/python3 detection/bruteforce_detector.py >> logs/bruteforce.log 2>&1
*/2 * * * * cd /home/kali/network-ids-platform && venv/bin/python3 detection/dos_detector.py >> logs/dos.log 2>&1
*/5 * * * * cd /home/kali/network-ids-platform && venv/bin/python3 detection/sqli_detector.py >> logs/sqli.log 2>&1
*/5 * * * * cd /home/kali/network-ids-platform && venv/bin/python3 detection/dns_tunnel_detector.py >> logs/dns_tunnel.log 2>&1
*/5 * * * * cd /home/kali/network-ids-platform && venv/bin/python3 ml/predict.py >> logs/ml_predict.log 2>&1
## Why these intervals

- Port scan, brute force, DoS: every 2 minutes (these use short lookback
  windows of 2-5 minutes in the scripts themselves, so frequent runs
  catch things quickly without excessive overlap).
- SQL injection, DNS tunneling, ML anomaly: every 5 minutes (these use
  longer lookback windows, 5-10 minutes, so running too frequently would
  just re-check mostly the same data).

## Notes

- Scripts use venv/bin/python3 directly (not source venv/bin/activate)
  since cron does not run an interactive shell - this is the standard way
  to use a virtual environment's Python from cron.
- Logs are written to logs/*.log for debugging; check these first if a
  detector isn't behaving as expected.
- The @reboot Docker line includes a 45-second delay to give the network
  interface and Docker daemon time to be ready after boot.
