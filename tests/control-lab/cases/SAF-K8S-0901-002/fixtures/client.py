#!/usr/bin/env python3
"""Bounded client for the case-owned in-cluster mock service."""
import json
import sys
import urllib.error
import urllib.request
from pathlib import Path

BASE = "http://aggregation.saf-0901-002.svc.cluster.local:8080"


def get(path):
    with urllib.request.urlopen(BASE + path, timeout=3) as response:
        return json.loads(response.read(4096))


def main():
    if len(sys.argv) != 3:
        raise SystemExit("usage: client.py submit|read KEY")
    operation, key = sys.argv[1:]
    if operation == "submit":
        requests = json.loads((Path(__file__).parent / "requests.json").read_text())
        body = json.dumps(requests[key], separators=(",", ":")).encode()
        request = urllib.request.Request(
            BASE + "/v1/contribute", data=body,
            headers={"Content-Type": "application/json",
                 "Authorization": "Bearer " + Path("/run/fixture-identity/token").read_text()}, method="POST")
        try:
            with urllib.request.urlopen(request, timeout=3) as response:
                result = json.loads(response.read(4096))
                status = response.status
        except urllib.error.HTTPError as error:
            result = json.loads(error.read(4096))
            status = error.code
        print(json.dumps({"request_key": key, "http_status": status,
                          "response": result}, sort_keys=True))
    elif operation == "read" and key in ("status", "result", "health"):
        path = {"status": "/v1/status", "result": "/v1/mock-result",
                "health": "/healthz"}[key]
        print(json.dumps(get(path), sort_keys=True))
    else:
        raise SystemExit("unsupported case operation")


if __name__ == "__main__":
    main()
