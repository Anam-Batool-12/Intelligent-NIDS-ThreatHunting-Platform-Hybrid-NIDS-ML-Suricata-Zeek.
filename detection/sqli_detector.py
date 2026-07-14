"""
Simple SQL Injection Confirmation Detector
"""

from elasticsearch import Elasticsearch

es = Elasticsearch("http://localhost:9200")

query = {
    "size": 1000,
    "query": {
        "range": {
            "@timestamp": {
                "gte": "now-10m"
            }
        }
    }
}

response = es.search(index="nids-alerts-*", body=query)

ip_sqli_count = {}

for hit in response["hits"]["hits"]:
    data = hit["_source"]

    alert_info = data.get("alert")
    if alert_info is None:
        continue

    signature = alert_info.get("signature")
    if signature is None:
        continue

    if "SQLi" not in signature:
        continue

    src_ip = data.get("src_ip")
    if src_ip is None:
        continue

    if src_ip not in ip_sqli_count:
        ip_sqli_count[src_ip] = 0

    ip_sqli_count[src_ip] = ip_sqli_count[src_ip] + 1

THRESHOLD = 3

for src_ip in ip_sqli_count:
    sqli_count = ip_sqli_count[src_ip]

    if sqli_count >= THRESHOLD:
        print("ALERT: " + src_ip + " ne " + str(sqli_count) + " baar SQL Injection try kiya - CONFIRMED ATTACK!")

        alert = {
            "detector": "sqli_confirmed",
            "src_ip": src_ip,
            "sqli_attempt_count": sqli_count
        }
        es.index(index="nids-python-alerts", document=alert)

print("Scan complete.")
