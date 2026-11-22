"""Make one ordinary fixed-path health request and emit bounded evidence."""
import json
import socket
import sys
import urllib.error
import urllib.request


if len(sys.argv) != 2 or not sys.argv[1].endswith("/healthz"):
    print(json.dumps({"path": "/healthz", "result": "invalid-fixture-arguments"}))
    raise SystemExit(64)

request = urllib.request.Request(sys.argv[1], method="GET")
try:
    with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(request, timeout=2) as response:
        body = response.read(129).decode("ascii", errors="replace").strip()
        print(json.dumps({"path": "/healthz", "result": "response",
                          "status": response.status, "body": body}, sort_keys=True))
except (urllib.error.URLError, TimeoutError, socket.timeout, OSError) as error:
    reason = getattr(error, "reason", error)
    print(json.dumps({"path": "/healthz", "result": "no-response",
                      "failure_class": type(reason).__name__}, sort_keys=True))
    raise SystemExit(2)
