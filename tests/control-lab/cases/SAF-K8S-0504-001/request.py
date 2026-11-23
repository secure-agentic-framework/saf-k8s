"""Send one fixed HTTP request from the owned mesh workload."""
import http.client
import json
import sys

path, marker = sys.argv[1:]
connection = http.client.HTTPConnection("saf-identity-target", 8080, timeout=5)
try:
    connection.request("GET", path, headers={"X-SAF-CASE": marker, "Connection": "close"})
    response = connection.getresponse()
    print(json.dumps({"status": response.status, "body": response.read(1024).decode().strip()}))
finally:
    connection.close()
