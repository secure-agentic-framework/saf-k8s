"""Evaluate a fixed synthetic backup event feed and receive its local notices."""

from http.server import BaseHTTPRequestHandler, HTTPServer
import json
from pathlib import Path
import sys
import urllib.request

SOURCE = "fixture-repository"
TARGET = "fixture-backup-marker"
OWNER = "fixture-backup-review"
EXPECTED_SOURCES = {SOURCE, "fixture-offline-custody"}


def alerts(rows):
    seen = set()
    fresh = set()
    current = []
    for row in rows:
        if row["id"] in seen:
            continue
        seen.add(row["id"])
        if not 80 <= row["observed"] <= 100:
            continue
        fresh.add(row["source"])
        if row["source"] == SOURCE and row["target"] == TARGET and row["actor"] != "fixture-approved":
            current.append({"event": row["id"], "kind": "review-access", "source": SOURCE, "owner": OWNER})
    for source in sorted(EXPECTED_SOURCES - fresh):
        current.append({"event": source, "kind": "review-coverage", "source": source, "owner": OWNER})
    return current


class Receiver(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()

    def do_POST(self):
        if self.path != "/alerts":
            self.send_error(404)
            return
        size = int(self.headers["Content-Length"])
        if not 0 < size <= 512:
            self.send_error(400)
            return
        notice = json.loads(self.rfile.read(size))
        print(json.dumps(notice), flush=True)
        self.send_response(204)
        self.end_headers()

    def log_message(self, _format, *_args):
        pass


if sys.argv[1] == "receive":
    HTTPServer(("0.0.0.0", 8080), Receiver).serve_forever()
else:
    notices = alerts(json.loads(Path("/fixture/events.json").read_text()))
    delivery = sys.argv[2] == "deliver"
    if delivery:
        for notice in notices:
            message = urllib.request.Request("http://fixture-backup-review:8080/alerts",
                                             data=json.dumps(notice).encode(),
                                             headers={"Content-Type": "application/json"})
            with urllib.request.urlopen(message, timeout=5) as result:
                if result.status != 204:
                    raise RuntimeError("Fixture alert was rejected")
    print(json.dumps({"evaluated": len(notices), "delivered": len(notices) if delivery else 0}))
