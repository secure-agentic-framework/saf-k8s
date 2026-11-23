"""One fixed fixture request from the independent Kubernetes client Pod."""
import http.client
import json
import sys

method, path, header, content = sys.argv[1:]
connection = http.client.HTTPConnection("saf-contract-gateway", 9080, timeout=5)
try:
    connection.request(method, path, body=content or None, headers={
        "Content-Type": "application/json", "X-Api-Client": header, "Connection": "close",
    })
    response = connection.getresponse()
    print(json.dumps({"status": response.status, "body": response.read(4096).decode().strip()}))
finally:
    connection.close()
