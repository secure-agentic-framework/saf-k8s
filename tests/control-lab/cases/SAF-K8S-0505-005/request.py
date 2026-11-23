"""Send one fixed request to the case-owned HTTP fixture."""
import http.client
import json
import sys

path, marker = sys.argv[1:]
connection = http.client.HTTPConnection("saf-0505-005-target.saf-test.svc.cluster.local", 8080, timeout=5)
try:
    connection.request("GET", path, headers={"X-SAF-CASE": marker, "Connection": "close"})
    response = connection.getresponse()
    print(json.dumps({"status": response.status, "body": response.read(1024).decode().strip()}))
finally:
    connection.close()
