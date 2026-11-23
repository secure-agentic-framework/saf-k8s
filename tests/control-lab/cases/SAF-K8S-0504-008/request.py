"""Send one fixed marker request to the owned ClusterIP Service."""
import http.client
import json
import sys

fixture = json.loads(sys.argv[1])
connection = http.client.HTTPConnection("marker-backend", 8080, timeout=4)
try:
    connection.request(fixture["method"], fixture["path"], body=fixture.get("post"),
                       headers={"X-Case-Grant": fixture["header"], "X-Case-Request": fixture["id"]})
    response = connection.getresponse()
    print(json.dumps({"status": response.status, "body": response.read(1024).decode().strip()}))
finally:
    connection.close()
