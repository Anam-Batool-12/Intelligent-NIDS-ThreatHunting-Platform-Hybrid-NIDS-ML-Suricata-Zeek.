"""
Simple DoS (Denial of Service) Detector

"""

from elasticsearch import Elasticsearch

es = Elasticsearch("http://localhost:9200")

query = {
    "size": 1000,
    "query": {
        "range": {
            "@timestamp": {
                "gte": "now-2m"
            }
        }
    }
}

response = es.search(index="nids-conn-*", body=query)

ip_connection_count = {}

for hit in response["hits"]["hits"]:
    data = hit["_source"]
    src_ip = data.get("id.orig_h")

    if src_ip is None:
        continue

    if src_ip not in ip_connection_count:
        ip_connection_count[src_ip] = 0

    ip_connection_count[src_ip] = ip_connection_count[src_ip] + 1

THRESHOLD = 100

for src_ip in ip_connection_count:
    total_connections = ip_connection_count[src_ip]

    if total_connections >= THRESHOLD:
        print("ALERT: " + src_ip + " ne " + str(total_connections) + " connections bheje sirf 2 minute mein!")

        alert = {
            "detector": "dos",
            "src_ip": src_ip,
            "total_connections": total_connections
        }
        es.index(index="nids-python-alerts", document=alert)

print("Scan complete.")
