"""Check one fixed owned Service endpoint and classify only handshake timeouts as isolation."""
import http.client
import json
import sys

request = http.client.HTTPConnection(sys.argv[1], port=8080, timeout=2.5)
try:
    try:
        request.connect()
    except TimeoutError:
        print(json.dumps({"transport": "connect_timeout"}))
    else:
        request.request("GET", "/")
        response = request.getresponse()
        print(json.dumps({"transport": "http", "status": response.status,
                          "body": response.read(128).decode().strip()}))
finally:
    request.close()
