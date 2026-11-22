"""Request one fixed case route and emit only bounded response evidence."""
import json
import sys
from urllib.error import HTTPError
from urllib.request import ProxyHandler, build_opener

opener = build_opener(ProxyHandler({}))

if (len(sys.argv) != 2
        or sys.argv[1] not in {
            "http://saf-0902-009-filter:8080/fixture",
            "http://saf-0902-009-filter:8080/intended",
            "http://saf-0902-009-filter:8080/at-cap",
            "http://saf-0902-009-filter:8080/over-cap",
        }):
    raise SystemExit("client accepts only the case-owned in-cluster Service URL")
try:
    with opener.open(sys.argv[1], timeout=5) as response:
        status, body = response.status, response.read(128)
except HTTPError as error:
    status, body = error.code, error.read(128)
print(json.dumps({"status": status, "body": body.decode("utf-8"),
                  "body_bytes": len(body)}, sort_keys=True))
