"""Open one TLS socket to the owned Kubernetes fixture."""
import http.client
import json
import socket
import ssl
import sys

inputs = json.load(sys.stdin)
context = ssl.create_default_context(cadata=inputs["ca"])
try:
    sock = socket.create_connection((inputs["address"], 6443), timeout=2.5)
except TimeoutError:
    print(json.dumps({"result": "tcp_timeout"}))
else:
    with sock, context.wrap_socket(sock, server_hostname="kubernetes.default.svc") as api:
        api.sendall(b"GET /version HTTP/1.1\r\nHost: kubernetes.default.svc\r\nConnection: close\r\n\r\n")
        response = http.client.HTTPResponse(api)
        response.begin()
        body = json.loads(response.read(16384))
        print(json.dumps({"result": "verified_api_response", "status": response.status,
                          "kubernetes_version": body.get("gitVersion"),
                          "from_kubernetes": response.status == 200 or body.get("kind") == "Status"}))
