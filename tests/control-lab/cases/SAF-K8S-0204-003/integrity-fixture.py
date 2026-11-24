"""Compare owned observations and receive attributed alerts in separate Pods."""

from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import os
from pathlib import Path
import sys
import time
from urllib.error import URLError
from urllib.request import ProxyHandler, Request, build_opener

PORT = 18082
APPROVED_PATH = "/baseline/drift-marker.txt"
WRITABLE_PATH = "/state/approved-marker.txt"


class Receipt(BaseHTTPRequestHandler):
    def log_message(self, *_args):
        pass

    def body(self, status, data):
        payload = json.dumps(data).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):
        self.body(200, self.server.rows)

    def do_POST(self):
        size = int(self.headers.get("Content-Length", "0"))
        if self.path != "/alerts" or not 0 < size < 20000:
            self.body(400, {})
            return
        event = json.loads(self.rfile.read(size))
        if event["fixture_event_id"] in self.server.rows:
            self.body(409, {})
            return
        key = event["fixture_event_id"]
        self.server.rows[key] = event
        self.body(201, {"accepted": key})


def receive():
    with HTTPServer(("0.0.0.0", PORT), Receipt) as server:
        server.rows = {}
        server.serve_forever()


def compare():
    configured = json.loads(Path("/samples/verified.json").read_text())
    approved = configured["approved"]
    rows = {}
    alerts = {}
    client = build_opener(ProxyHandler({}))
    target_url = f"http://{os.environ['FIXTURE_RECEIVER_IP']}:18082/alerts"
    deadline = time.monotonic() + 25
    while True:
        try:
            with client.open(target_url, timeout=2) as health:
                assert json.load(health) == {}
            break
        except (URLError, TimeoutError):
            if time.monotonic() > deadline:
                raise RuntimeError("The owned receiver Service did not become reachable")
            time.sleep(0.5)
    for label, sample in configured["observations"].items():
        assert sample["path"] == APPROVED_PATH and sample["state_path"] == WRITABLE_PATH
        assert sample["image_id"] == configured["image_id"]
        assert sample["initial_sha256"] == approved
        assert sample["state_initial_sha256"] != sample["state_sha256"]
        rows[label] = {"same_bytes_match": sample["same_content_sha256"] == approved,
                       "approved_volume_changed": True, "drift": sample["observed_sha256"] != approved}
        if rows[label]["drift"]:
            event = {"fixture_event_id": sample["pod_uid"] + ":image-file",
                     "pod_uid": sample["pod_uid"], "image_id": sample["image_id"], "path": APPROVED_PATH,
                     "baseline_sha256": approved, "observed_sha256": sample["observed_sha256"]}
            target = Request(target_url, data=json.dumps(event).encode(),
                             headers={"Content-Type": "application/json"})
            with client.open(target, timeout=6) as response:
                alerts[label] = json.load(response)["accepted"]
    print(json.dumps({"comparisons": rows, "delivery_acks": alerts}))


if __name__ == "__main__":
    if sys.argv[1] == "receive":
        receive()
    else:
        compare()
