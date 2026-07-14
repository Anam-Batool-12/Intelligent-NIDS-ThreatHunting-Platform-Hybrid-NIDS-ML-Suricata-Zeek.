"""
Simple Brute Force Detector
"""

from elasticsearch import Elasticsearch

es = Elasticsearch("http://localhost:9200")

LOGIN_PORTS = [22, 21, 3389]

query = {
    "size": 1000,
    "query": {
        "range": {
            "@timestamp": {
                "gte": "now-5m"
            }
        }
    }
}

response = es.search(index="nids-conn-*", body=query)

ip_port_attempts = {}

for hit in response["hits"]["hits"]:
    data = hit["_source"]
    src_ip = data.get("id.orig_h")
    dest_port = data.get("id.resp_p")

    if src_ip is None or dest_port is None:
        continue

    if dest_port not in LOGIN_PORTS:
        continue

    key = src_ip + "-" + str(dest_port)

    if key not in ip_port_attempts:
        ip_port_attempts[key] = 0

    ip_port_attempts[key] = ip_port_attempts[key] + 1

THRESHOLD = 10

for key in ip_port_attempts:
    attempt_count = ip_port_attempts[key]

    if attempt_count >= THRESHOLD:
        parts = key.rsplit("-", 1)
        src_ip = parts[0]
        dest_port = parts[1]

        print("ALERT: " + src_ip + " ne port " + dest_port + " pe " + str(attempt_count) + " baar try kiya!")

        alert = {
            "detector": "bruteforce",
            "src_ip": src_ip,
            "dest_port": dest_port,
            "attempt_count": attempt_count
        }
        es.index(index="nids-python-alerts", document=alert)

print("Scan complete.")
